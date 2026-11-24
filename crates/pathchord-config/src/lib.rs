//! Shared configuration source and role-aware loading primitives.

mod layout;
mod transaction;
pub use transaction::{ResourceChange, SourceTransaction};

pub use layout::{Role, RoleLayout, SelectedSource, SourceOrigin};

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use tokio::io::AsyncReadExt;

use pathchord_policy::{EgressServiceSpec, KubeConfig};

pub const MAX_CONFIGURATION_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CONFIGURATION_FILES: usize = 1024;
pub const MAX_CONFIGURATION_DEPTH: usize = 16;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    #[error("the current account's home directory could not be determined")]
    MissingHome,
    #[error("configuration transaction failed: {0}")]
    Transaction(&'static str),
    #[error("set only one of PATHCHORD_CONFIG and PATHCHORD_CONFIG_DIR")]
    ConflictingEnvironment,
    #[error("a configuration directory was required")]
    ExpectedDirectory,
    #[error("private path for {0} must be outside the scanned resource tree")]
    PrivatePath(&'static str),
    #[error("configuration source I/O failed")]
    Io,
    #[error("configuration exceeds the size bound")]
    TooLarge,
    #[error("configuration directory contains too many files")]
    TooManyFiles,
    #[error("configuration directory exceeds the recursion depth bound")]
    TooDeep,
    #[error("configuration directory contains no supported files")]
    EmptyDirectory,
    #[error("configuration source must contain regular files and directories")]
    UnsupportedSource,
    #[error("configuration directory entries must not be symbolic links")]
    Symlink,
}

pub async fn load_configuration_documents(
    path: impl Into<PathBuf>,
) -> Result<Vec<String>, ConfigurationError> {
    let source = ConfigurationSource::bind(path.into()).await?;
    Ok(source.load().await?.documents)
}

#[derive(Debug, Error)]
pub enum EgressConfigurationError {
    #[error("Egress configuration source failed: {0}")]
    Source(#[from] ConfigurationError),
    #[error("Egress resource parsing failed: {0}")]
    Parse(#[from] pathchord_policy::ConfigError),
    #[error("Egress configuration must contain exactly one EgressService; found {0}")]
    ServiceCount(usize),
    #[error("resource kind {kind} is not valid in Egress configuration")]
    UnsupportedKind { kind: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressServiceResource {
    pub name: String,
    pub namespace: String,
    pub spec: EgressServiceSpec,
}

pub fn parse_egress_service_documents<'a>(
    inputs: impl IntoIterator<Item = &'a str>,
) -> Result<EgressServiceResource, EgressConfigurationError> {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    reject_ingress_resource_kinds(&inputs)?;
    let kube = KubeConfig::from_service_documents(inputs.iter().copied())?;
    let mut service = None;
    let mut service_count = 0;
    for resource in kube.resources {
        let Some((metadata, spec)) = resource.egress_service() else {
            return Err(EgressConfigurationError::UnsupportedKind {
                kind: resource.kind().to_owned(),
            });
        };
        service_count += 1;
        service = Some(EgressServiceResource {
            name: metadata.name.clone(),
            namespace: metadata.namespace.clone(),
            spec: spec.clone(),
        });
    }
    if service_count != 1 {
        return Err(EgressConfigurationError::ServiceCount(service_count));
    }
    Ok(service.expect("service count was checked"))
}

fn reject_ingress_resource_kinds(inputs: &[&str]) -> Result<(), EgressConfigurationError> {
    for input in inputs {
        for value in serde_yaml::from_str_multi::<serde_json::Value>(input)
            .map_err(pathchord_policy::ConfigError::Yaml)?
        {
            if value.is_null() {
                continue;
            }
            let values = if value.get("kind").and_then(serde_json::Value::as_str) == Some("List") {
                value
                    .get("items")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            } else {
                vec![value]
            };
            for resource in values {
                let kind = resource
                    .get("kind")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if kind != "EgressService" {
                    return Err(EgressConfigurationError::UnsupportedKind {
                        kind: kind.to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

pub async fn load_egress_service(
    path: impl Into<PathBuf>,
) -> Result<(ConfigurationSource, EgressServiceResource), EgressConfigurationError> {
    let source = ConfigurationSource::bind(path.into()).await?;
    let loaded = source.load().await?;
    let service = parse_egress_service_documents(loaded.documents.iter().map(String::as_str))?;
    Ok((source, service))
}

#[derive(Debug)]
pub struct ConfigurationSource {
    path: PathBuf,
    directory: bool,
}

pub struct ConfigurationDocuments {
    pub documents: Vec<String>,
    pub directories: BTreeSet<PathBuf>,
    pub files: Vec<PathBuf>,
}

impl ConfigurationSource {
    pub async fn bind(path: PathBuf) -> Result<Self, ConfigurationError> {
        // The explicitly selected root may be a symlink. Resolve it once;
        // entries discovered inside a directory are never followed.
        let path = tokio::fs::canonicalize(path)
            .await
            .map_err(|_| ConfigurationError::Io)?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| ConfigurationError::Io)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(ConfigurationError::UnsupportedSource);
        }
        Ok(Self {
            path,
            directory: metadata.is_dir(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn base_directory(&self) -> &Path {
        if self.directory {
            &self.path
        } else {
            self.path.parent().expect("a canonical file has a parent")
        }
    }

    pub fn is_directory(&self) -> bool {
        self.directory
    }

    pub fn visible_descendant(&self, path: &Path) -> bool {
        path.strip_prefix(&self.path).is_ok_and(|relative| {
            relative.components().all(|component| match component {
                Component::Normal(name) => !ignored_name(name),
                _ => false,
            })
        })
    }

    /// Check a private path even when its leaf has not been created yet.
    pub fn validate_private_path(
        &self,
        field: &'static str,
        path: &Path,
    ) -> Result<(), ConfigurationError> {
        if !self.directory {
            return Ok(());
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|_| ConfigurationError::Io)?
                .join(path)
        };
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            if component == Component::ParentDir {
                normalized.pop();
                continue;
            }
            normalized.push(component);
            match std::fs::canonicalize(&normalized) {
                Ok(canonical) => normalized = canonical,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(ConfigurationError::Io),
            }
        }
        if normalized.starts_with(&self.path) {
            return Err(ConfigurationError::PrivatePath(field));
        }
        Ok(())
    }

    pub async fn load(&self) -> Result<ConfigurationDocuments, ConfigurationError> {
        let root = self.base_directory().to_owned();
        let guard = SourceTransaction::read_guard(root.clone()).await?;
        let loaded = self.load_unlocked().await;
        if guard.lock_appeared() {
            let guard = SourceTransaction::read_guard(root).await?;
            let mut loaded = self.load_unlocked().await?;
            guard.restore_view(&mut loaded, self);
            Ok(loaded)
        } else {
            let mut loaded = loaded?;
            guard.restore_view(&mut loaded, self);
            Ok(loaded)
        }
    }

    pub async fn load_unlocked(&self) -> Result<ConfigurationDocuments, ConfigurationError> {
        let metadata = tokio::fs::symlink_metadata(&self.path)
            .await
            .map_err(|_| ConfigurationError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigurationError::Symlink);
        }
        if metadata.is_dir() != self.directory || (!self.directory && !metadata.is_file()) {
            return Err(ConfigurationError::UnsupportedSource);
        }
        let mut directories = BTreeSet::new();
        let mut files = Vec::new();
        if self.directory {
            let mut pending = vec![(self.path.clone(), 0_usize)];
            while let Some((directory, depth)) = pending.pop() {
                directories.insert(directory.clone());
                let mut entries = tokio::fs::read_dir(&directory)
                    .await
                    .map_err(|_| ConfigurationError::Io)?;
                while let Some(entry) = entries
                    .next_entry()
                    .await
                    .map_err(|_| ConfigurationError::Io)?
                {
                    if ignored_name(&entry.file_name()) {
                        continue;
                    }
                    let path = entry.path();
                    let metadata = tokio::fs::symlink_metadata(&path)
                        .await
                        .map_err(|_| ConfigurationError::Io)?;
                    if metadata.file_type().is_symlink() {
                        return Err(ConfigurationError::Symlink);
                    }
                    if metadata.is_dir() {
                        if depth >= MAX_CONFIGURATION_DEPTH {
                            return Err(ConfigurationError::TooDeep);
                        }
                        pending.push((path, depth + 1));
                    } else if is_configuration_file(&path) {
                        if !metadata.is_file() {
                            return Err(ConfigurationError::UnsupportedSource);
                        }
                        files.push(path);
                        if files.len() > MAX_CONFIGURATION_FILES {
                            return Err(ConfigurationError::TooManyFiles);
                        }
                    }
                }
            }
            if files.is_empty() {
                return Err(ConfigurationError::EmptyDirectory);
            }
            files.sort_by(|a, b| {
                a.strip_prefix(&self.path)
                    .expect("configuration file is under its source")
                    .cmp(
                        b.strip_prefix(&self.path)
                            .expect("configuration file is under its source"),
                    )
            });
        } else {
            files.push(self.path.clone());
        }
        let mut documents = Vec::with_capacity(files.len());
        let mut remaining = MAX_CONFIGURATION_BYTES;
        for path in &files {
            let bytes = read_bounded_file(path, remaining).await?;
            remaining -= bytes.len() as u64;
            documents.push(String::from_utf8(bytes).map_err(|_| ConfigurationError::Io)?);
        }
        Ok(ConfigurationDocuments {
            documents,
            directories,
            files,
        })
    }
}

fn ignored_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with('.') || name.starts_with('#') || name.ends_with('~')
}

pub fn is_configuration_file(path: &Path) -> bool {
    path.file_name().is_some_and(|name| !ignored_name(name))
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                ["yaml", "yml", "json"]
                    .iter()
                    .any(|allowed| extension.eq_ignore_ascii_case(allowed))
            })
}

async fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ConfigurationError> {
    let before = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ConfigurationError::Io)?;
    if before.file_type().is_symlink() {
        return Err(ConfigurationError::Symlink);
    }
    if !before.is_file() {
        return Err(ConfigurationError::UnsupportedSource);
    }
    if before.len() > maximum {
        return Err(ConfigurationError::TooLarge);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ConfigurationError::Io)?;
    let opened = file.metadata().await.map_err(|_| ConfigurationError::Io)?;
    let after = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ConfigurationError::Io)?;
    if after.file_type().is_symlink() {
        return Err(ConfigurationError::Symlink);
    }
    if !opened.is_file() || !after.is_file() {
        return Err(ConfigurationError::UnsupportedSource);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
        {
            return Err(ConfigurationError::Io);
        }
    }
    if opened.len() > maximum {
        return Err(ConfigurationError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ConfigurationError::Io)?;
    if bytes.len() as u64 > maximum {
        return Err(ConfigurationError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(super) struct Directory(pub(super) PathBuf);

    impl Directory {
        pub(super) fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pc-config-source-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn private_paths_resolve_from_a_directory_but_stay_outside_its_tree() {
        let directory = Directory::new();
        let resources = directory.0.join("resources");
        std::fs::create_dir(&resources).unwrap();
        let source = ConfigurationSource::bind(resources).await.unwrap();
        assert!(
            source
                .validate_private_path("identity", &source.path().join("nested/key"))
                .is_err()
        );
        let sibling = source.base_directory().join("../private/key");
        source.validate_private_path("identity", &sibling).unwrap();
    }

    #[tokio::test]
    async fn recursively_loads_supported_files_in_relative_path_order() {
        let directory = Directory::new();
        std::fs::create_dir(directory.0.join("nested")).unwrap();
        std::fs::create_dir(directory.0.join(".hidden")).unwrap();
        for (path, body) in [
            ("b.yml", "second"),
            ("a.JSON", "first"),
            ("nested/c.yaml", "third"),
            ("runtime.db", "ignored"),
            (".secret.yml", "ignored"),
            (".hidden/x.yaml", "ignored"),
            ("pending.yaml~", "ignored"),
            ("#draft.yaml", "ignored"),
        ] {
            std::fs::write(directory.0.join(path), body).unwrap();
        }
        let source = ConfigurationSource::bind(directory.0.clone())
            .await
            .unwrap();
        let loaded = source.load().await.unwrap();
        assert_eq!(loaded.documents, ["first", "second", "third"]);
        assert_eq!(loaded.directories.len(), 2);
    }

    #[tokio::test]
    async fn rejects_empty_directories_and_whole_bundle_size_overflow() {
        let directory = Directory::new();
        let source = ConfigurationSource::bind(directory.0.clone())
            .await
            .unwrap();
        assert!(matches!(
            source.load().await,
            Err(ConfigurationError::EmptyDirectory)
        ));
        std::fs::write(
            directory.0.join("one.yml"),
            vec![b' '; MAX_CONFIGURATION_BYTES as usize],
        )
        .unwrap();
        std::fs::write(directory.0.join("two.json"), b"{}").unwrap();
        assert!(matches!(
            source.load().await,
            Err(ConfigurationError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn rejects_excessive_file_count_and_directory_depth() {
        let directory = Directory::new();
        let source = ConfigurationSource::bind(directory.0.clone())
            .await
            .unwrap();
        for index in 0..=MAX_CONFIGURATION_FILES {
            std::fs::write(directory.0.join(format!("{index}.yaml")), b"").unwrap();
        }
        assert!(matches!(
            source.load().await,
            Err(ConfigurationError::TooManyFiles)
        ));
        let deep = Directory::new();
        let mut path = deep.0.clone();
        for _ in 0..=MAX_CONFIGURATION_DEPTH {
            path.push("nested");
            std::fs::create_dir(&path).unwrap();
        }
        assert!(matches!(
            ConfigurationSource::bind(deep.0.clone())
                .await
                .unwrap()
                .load()
                .await,
            Err(ConfigurationError::TooDeep)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_visible_child_symlinks_without_following_them() {
        let directory = Directory::new();
        let external = Directory::new();
        std::fs::write(external.0.join("external.yaml"), "private").unwrap();
        std::os::unix::fs::symlink(&external.0, directory.0.join("linked")).unwrap();
        let source = ConfigurationSource::bind(directory.0.clone())
            .await
            .unwrap();
        assert!(matches!(
            source.load().await,
            Err(ConfigurationError::Symlink)
        ));
    }

    #[test]
    fn parses_one_egress_service_without_ingress_resources() {
        let source = "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge}\nspec: {identity: egress.key.json}\n";
        let service = parse_egress_service_documents([source]).unwrap();
        assert_eq!(service.name, "edge");
        assert_eq!(service.namespace, "default");
        assert_eq!(
            service.spec.identity.as_deref(),
            Some(Path::new("egress.key.json"))
        );
    }

    #[test]
    fn repository_egress_example_is_service_scoped() {
        let service =
            parse_egress_service_documents([include_str!("../../../examples/egress-service.yaml")])
                .unwrap();
        assert_eq!(service.name, "exit");
        assert_eq!(service.spec.egress_id.as_deref(), Some("exit"));
    }

    #[test]
    fn rejects_ingress_only_resource_kinds() {
        let source = "---\napiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge}\nspec: {identity: egress.key.json}\n---\napiVersion: pathchord.io/v1\nkind: NodeProbePolicy\nmetadata: {name: probes}\nspec: {target: {host: probe.example, port: 443}}\n";
        assert!(matches!(
            parse_egress_service_documents([source]),
            Err(EgressConfigurationError::UnsupportedKind { kind }) if kind == "NodeProbePolicy"
        ));
    }

    #[test]
    fn rejects_every_ingress_resource_family_before_role_validation() {
        for kind in [
            "Listener",
            "TransitProxy",
            "Subscription",
            "EgressRule",
            "ProxyRule",
            "TrafficPolicy",
            "DNSPolicy",
            "FallbackPolicy",
            "GeoSiteDatabase",
            "GeoIpDatabase",
            "NodeProbePolicy",
        ] {
            let source = format!(
                "---\napiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {{name: edge}}\nspec: {{identity: egress.key.json}}\n---\napiVersion: pathchord.io/v1\nkind: {kind}\nmetadata: {{name: forbidden}}\nspec: {{}}\n"
            );
            assert!(matches!(
                parse_egress_service_documents([source.as_str()]),
                Err(EgressConfigurationError::UnsupportedKind { kind: actual }) if actual == kind
            ));
        }
    }

    #[test]
    fn requires_exactly_one_egress_service() {
        let none = "";
        assert!(matches!(
            parse_egress_service_documents([none]),
            Err(EgressConfigurationError::ServiceCount(0))
        ));

        let multiple = "---\napiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge-a}\nspec: {identity: a.key.json}\n---\napiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge-b}\nspec: {identity: b.key.json}\n";
        assert!(matches!(
            parse_egress_service_documents([multiple]),
            Err(EgressConfigurationError::ServiceCount(2))
        ));
    }
}
