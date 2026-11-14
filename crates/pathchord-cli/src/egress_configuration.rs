//! Resolve role startup settings before opening identity files or sockets.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use pathchord_policy::{EgressServiceSpec, KubeConfig};

use crate::configuration::ConfigSelection;
use crate::{
    CliError, DEFAULT_EGRESS_BIND, DEFAULT_EGRESS_SOCKET_PATH, DEFAULT_MAX_CONCURRENT_PATHS,
    EgressArgs,
};

pub(crate) struct EgressConfiguration {
    pub bind: SocketAddr,
    pub egress_id: String,
    pub identity: PathBuf,
    pub authorization_db: PathBuf,
    pub control_socket: PathBuf,
    pub max_concurrent_paths: usize,
    pub max_wire_bandwidth_bps: u64,
    pub max_inbound_target_connections: usize,
    pub remote_dns_only: bool,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
    pub web_bind: Option<SocketAddr>,
    pub web_token_file: Option<PathBuf>,
    pub web_origins: Vec<String>,
    pub web_protected_transport: bool,
}

pub(crate) async fn resolve(args: EgressArgs) -> Result<EgressConfiguration, CliError> {
    let source = ConfigSelection::resolve(args.config.as_deref(), args.config_dir.as_deref())?;
    resolve_source(args, source).await
}

async fn resolve_source(
    args: EgressArgs,
    source: ConfigSelection,
) -> Result<EgressConfiguration, CliError> {
    // A complete legacy CLI invocation can run without an installed default
    // directory. An explicitly selected source must always be readable.
    if !source.explicit
        && !source.path.try_exists()?
        && args.egress_id.is_some()
        && args.identity.is_some()
    {
        return merge(args, None, Path::new("."));
    }
    source.validate()?;
    let documents = pathchord_ingress::load_configuration_documents(source.path.clone())
        .await
        .map_err(|error| CliError::ConfigurationLoad {
            path: source.path.clone(),
            source: error,
        })?;
    let kube = KubeConfig::from_service_documents(documents.iter().map(String::as_str))?;
    let mut services = kube
        .resources
        .iter()
        .filter_map(|resource| resource.egress_service());
    let service = services.next();
    if services.next().is_some() {
        return Err(CliError::EgressConfiguration(
            "select exactly one EgressService per process",
        ));
    }
    let base = if source.directory {
        source.path.as_path()
    } else {
        source.path.parent().unwrap_or(Path::new("."))
    };
    merge(
        args,
        service.map(|(metadata, spec)| (metadata.name.as_str(), spec)),
        base,
    )
}

fn merge(
    args: EgressArgs,
    service: Option<(&str, &EgressServiceSpec)>,
    base: &Path,
) -> Result<EgressConfiguration, CliError> {
    let defaults = EgressServiceSpec::default();
    let spec = service.map_or(&defaults, |(_, spec)| spec);
    let path = |cli: Option<PathBuf>, config: &Option<PathBuf>, fallback: &str| {
        cli.or_else(|| {
            config.as_ref().map(|value| {
                if value.is_absolute() {
                    value.clone()
                } else {
                    base.join(value)
                }
            })
        })
        .unwrap_or_else(|| PathBuf::from(fallback))
    };
    let egress_id = args
        .egress_id
        .or_else(|| spec.egress_id.clone())
        .or_else(|| service.map(|(name, _)| name.to_owned()))
        .ok_or(CliError::EgressConfiguration(
            "egressId or --egress-id is required",
        ))?;
    let identity = path(args.identity, &spec.identity, "");
    if identity.as_os_str().is_empty() {
        return Err(CliError::EgressConfiguration(
            "identity or --identity is required",
        ));
    }
    let control_socket = args
        .control_socket
        .or_else(|| {
            spec.control_socket.as_ref().map(|value| {
                if value.is_absolute() {
                    value.clone()
                } else {
                    base.join(value)
                }
            })
        })
        .unwrap_or_else(default_egress_socket_path);
    let resolved = EgressConfiguration {
        bind: args
            .bind
            .or(spec.bind)
            .unwrap_or_else(|| DEFAULT_EGRESS_BIND.parse().expect("constant address")),
        egress_id,
        identity,
        authorization_db: path(
            args.authorization_db,
            &spec.authorization_db,
            "pathchord-authorizations.db",
        ),
        control_socket,
        max_concurrent_paths: DEFAULT_MAX_CONCURRENT_PATHS,
        max_wire_bandwidth_bps: args
            .max_wire_bandwidth_bps
            .or(spec.max_wire_bandwidth_bps)
            .unwrap_or(1_000_000_000),
        max_inbound_target_connections: args
            .max_inbound_target_connections
            .or(spec.max_inbound_target_connections)
            .unwrap_or(4096),
        remote_dns_only: spec.remote_dns_only.unwrap_or(false),
        quota_remaining: args.quota_remaining.or(spec.quota_remaining),
        traffic_multiplier_basis_points: args
            .traffic_multiplier_basis_points
            .or(spec.traffic_multiplier_basis_points)
            .unwrap_or(10_000),
        web_bind: args.web_bind.or(spec.web_bind),
        web_token_file: args.web_token_file.or_else(|| {
            spec.web_token_file.as_ref().map(|value| {
                if value.is_absolute() {
                    value.clone()
                } else {
                    base.join(value)
                }
            })
        }),
        web_origins: if args.web_origins.is_empty() {
            spec.web_origins.iter().cloned().collect()
        } else {
            args.web_origins
        },
        web_protected_transport: args
            .web_protected_transport
            .or(spec.web_protected_transport)
            .unwrap_or(false),
    };
    EgressServiceSpec {
        egress_id: Some(resolved.egress_id.clone()),
        identity: Some(resolved.identity.clone()),
        authorization_db: Some(resolved.authorization_db.clone()),
        control_socket: Some(resolved.control_socket.clone()),
        max_wire_bandwidth_bps: Some(resolved.max_wire_bandwidth_bps),
        max_inbound_target_connections: Some(resolved.max_inbound_target_connections),
        traffic_multiplier_basis_points: Some(resolved.traffic_multiplier_basis_points),
        ..EgressServiceSpec::default()
    }
    .validate()
    .map_err(CliError::EgressConfiguration)?;
    Ok(resolved)
}

fn default_egress_socket_path() -> PathBuf {
    crate::configuration::default_control_socket("egress.sock", DEFAULT_EGRESS_SOCKET_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    fn args(options: &[&str]) -> EgressArgs {
        let cli = Cli::parse_from(
            ["pathchord", "egress"]
                .into_iter()
                .chain(options.iter().copied()),
        );
        match cli.command {
            Command::Egress(args) => args,
            _ => unreachable!(),
        }
    }

    #[test]
    fn cli_settings_override_resource_and_resource_paths_use_source_directory() {
        let spec = EgressServiceSpec {
            bind: Some("127.0.0.1:1234".parse().unwrap()),
            identity: Some("identity.json".into()),
            authorization_db: Some("auth.db".into()),
            remote_dns_only: Some(true),
            web_protected_transport: Some(true),
            ..Default::default()
        };
        let base = std::env::temp_dir().join("pathchord-config");
        let config = merge(
            args(&[
                "--bind",
                "127.0.0.1:4321",
                "--authorization-db",
                "cli.db",
                "--web-protected-transport=false",
            ]),
            Some(("edge", &spec)),
            &base,
        )
        .unwrap();
        assert_eq!(config.bind.port(), 4321);
        assert_eq!(config.egress_id, "edge");
        assert_eq!(config.identity, base.join("identity.json"));
        assert_eq!(config.authorization_db, Path::new("cli.db"));
        assert!(config.remote_dns_only);
        assert!(!config.web_protected_transport);
    }

    #[tokio::test]
    async fn missing_default_permits_complete_cli_but_explicit_missing_source_fails() {
        let missing =
            std::env::temp_dir().join(format!("pathchord-no-config-{}", std::process::id()));
        let cli = args(&["--egress-id", "edge", "--identity", "cli.json"]);
        assert!(
            resolve_source(
                cli.clone(),
                ConfigSelection {
                    path: missing.clone(),
                    directory: true,
                    explicit: false
                }
            )
            .await
            .is_ok()
        );
        assert!(
            resolve_source(
                cli,
                ConfigSelection {
                    path: missing,
                    directory: true,
                    explicit: true
                }
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn service_only_directory_is_valid_and_multiple_services_are_rejected() {
        let root =
            std::env::temp_dir().join(format!("pathchord-egress-config-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let doc = "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge}\nspec: {identity: identity.json}\n";
        std::fs::write(root.join("edge.yaml"), doc).unwrap();
        let source = || ConfigSelection {
            path: root.clone(),
            directory: true,
            explicit: true,
        };
        let config = resolve_source(args(&[]), source()).await.unwrap();
        assert_eq!(config.identity, root.join("identity.json"));
        std::fs::write(
            root.join("second.yaml"),
            doc.replace("name: edge", "name: other"),
        )
        .unwrap();
        assert!(matches!(
            resolve_source(args(&[]), source()).await,
            Err(CliError::EgressConfiguration(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn namespaced_service_defaults_to_the_canonical_name_for_enrollment_and_noise() {
        let root = std::env::temp_dir().join(format!(
            "pathchord-egress-namespaced-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("edge.yaml"), "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge, namespace: tenant-a}\nspec: {identity: identity.key}\n").unwrap();
        let config = resolve_source(
            args(&[]),
            ConfigSelection {
                path: root.clone(),
                directory: true,
                explicit: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(config.egress_id, "edge");
        assert_eq!(config.identity, root.join("identity.key"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
