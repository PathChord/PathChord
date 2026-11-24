use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use pathchord_config::{
    ConfigurationDocuments, ConfigurationError, ConfigurationSource, ResourceChange, Role,
    RoleLayout, SelectedSource, SourceTransaction,
};
use pathchord_policy::{CompiledPolicy, Generation, KubeConfig, PolicyConfig};
use serde_json::{Value, json};

use super::{Output, generate_static_keypair, write_identity};

const MANAGED: &str = "managed.yaml";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TargetRole {
    Ingress,
    Egress,
}

impl From<TargetRole> for Role {
    fn from(role: TargetRole) -> Self {
        match role {
            TargetRole::Ingress => Self::Ingress,
            TargetRole::Egress => Self::Egress,
        }
    }
}

#[derive(Debug, Args)]
pub(super) struct ConfigArgs {
    /// Service role. Defaults to Ingress for inspection and editing.
    #[arg(long, global = true, value_enum)]
    role: Option<TargetRole>,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Create a minimal role configuration and private directories.
    Init {
        #[arg(long)]
        both: bool,
        /// Explicitly generate missing identities without prompting.
        #[arg(long)]
        generate_identity: bool,
    },
    /// Validate the complete resource source.
    Validate,
    /// Report effective paths and their provenance.
    Paths,
    /// Show effective settings and authored resources.
    View {
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// Read a resource by kind and name.
    Get(Selector),
    /// Create a resource from a YAML manifest.
    Create {
        #[arg(short = 'f', long)]
        file: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
    /// Merge a YAML mapping into a managed resource.
    Patch {
        #[command(flatten)]
        selector: Selector,
        #[arg(short = 'f', long)]
        file: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
    /// Delete a managed resource.
    Delete {
        #[command(flatten)]
        selector: Selector,
        #[arg(long)]
        dry_run: bool,
    },
    /// Move resources from a hand-authored YAML file into managed.yaml.
    Adopt {
        #[arg(required_unless_present = "all_from", conflicts_with = "all_from")]
        resource: Option<String>,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[arg(long)]
        all_from: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
struct Selector {
    /// Resource in KIND/NAME form.
    resource: String,
    #[arg(short = 'n', long, default_value = "default")]
    namespace: String,
}

impl Selector {
    fn matches(&self, resource: &Value) -> bool {
        let Some((kind, name)) = self.resource.split_once('/') else {
            return false;
        };
        resource["kind"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(kind))
            && resource["metadata"]["name"].as_str() == Some(name)
            && resource["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                == self.namespace
    }
}

pub(super) async fn run(
    args: ConfigArgs,
    output: Output,
    file: Option<&Path>,
    directory: Option<&Path>,
    socket: Option<&Path>,
) -> Result<()> {
    if let ConfigCommand::Init {
        both,
        generate_identity,
    } = args.command
    {
        let roles =
            match (both, args.role) {
                (true, None) if file.is_none() && directory.is_none() => {
                    vec![Role::Ingress, Role::Egress]
                }
                (false, Some(role)) => vec![role.into()],
                _ => return Err(
                    "select exactly one of --role or --both, and use separate sources with --both"
                        .into(),
                ),
            };
        if both
            && ["PATHCHORD_CONFIG", "PATHCHORD_CONFIG_DIR"]
                .iter()
                .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        {
            return Err("--both requires distinct default sources; unset the configuration source environment variables".into());
        }
        let mut initialized = Vec::new();
        for role in roles {
            let layout = RoleLayout::current(role)?;
            let selection = SelectedSource::resolve(&layout, file, directory)?;
            initialized.push(init(role, &layout, &selection, generate_identity).await?);
        }
        return print(
            output,
            &json!({"development": both, "initialized": initialized}),
        );
    }
    let role = args.role.map_or(Role::Ingress, Role::from);
    let layout = RoleLayout::current(role)?;
    let selection = SelectedSource::resolve(&layout, file, directory)?;
    let source = selection.bind().await?;
    match args.command {
        ConfigCommand::Validate => {
            let loaded = source.load().await?;
            if let Err(error) = validate(role, &source, &loaded.documents) {
                let (code, message) = validation_diagnostic(error.as_ref());
                if !matches!(output, Output::Human) {
                    print(
                        output,
                        &json!({
                            "valid": false, "role": role.name(), "source": source.path(),
                            "error": {"code": code, "message": message},
                        }),
                    )?;
                }
                return Err(format!("{code} in {}: {message}", source.path().display()).into());
            }
            print(
                output,
                &json!({"valid": true, "role": role.name(), "source": source.path()}),
            )
        }
        ConfigCommand::View { reveal_secrets } => {
            if reveal_secrets
                && (!matches!(output, Output::Human)
                    || !std::io::stdout().is_terminal()
                    || !std::io::stdin().is_terminal())
            {
                return Err(
                    "--reveal-secrets requires an interactive terminal and human output".into(),
                );
            }
            let loaded = source.load().await?;
            let mut resources = loaded
                .documents
                .iter()
                .map(|text| resources(text))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            if !reveal_secrets {
                for resource in &mut resources {
                    redact(resource);
                }
            }
            let paths = paths(role, &layout, &selection, &source, &loaded, socket)?;
            print(
                output,
                &json!({"effective_paths": paths, "resources": resources}),
            )
        }
        ConfigCommand::Paths => {
            let loaded = source.load().await?;
            print(
                output,
                &paths(role, &layout, &selection, &source, &loaded, socket)?,
            )
        }
        ConfigCommand::Get(selector) => {
            let loaded = source.load().await?;
            validate(role, &source, &loaded.documents)?;
            for (file, text) in loaded.files.iter().zip(&loaded.documents) {
                if let Some(mut resource) = resources(text)?
                    .into_iter()
                    .find(|resource| selector.matches(resource))
                {
                    redact(&mut resource);
                    return print(output, &json!({"resource": resource, "source": file}));
                }
            }
            Err("resource not found".into())
        }
        command => edit(role, &source, command, output).await,
    }
}

fn validation_diagnostic(error: &(dyn std::error::Error + 'static)) -> (&'static str, String) {
    use pathchord_policy::ConfigError;
    let config_error = error.downcast_ref::<ConfigError>().or_else(|| {
        match error.downcast_ref::<pathchord_config::EgressConfigurationError>() {
            Some(pathchord_config::EgressConfigurationError::Parse(error)) => Some(error),
            _ => None,
        }
    });
    match config_error {
        Some(ConfigError::Yaml(error)) => (
            "CONFIG_PARSE_ERROR",
            error.location().map_or_else(
                || "invalid resource YAML".to_owned(),
                |location| {
                    format!(
                        "invalid resource YAML at line {}, column {}",
                        location.line(),
                        location.column()
                    )
                },
            ),
        ),
        Some(ConfigError::DuplicateResource { .. }) => {
            ("CONFIG_DUPLICATE_RESOURCE", error.to_string())
        }
        Some(ConfigError::RetiredField { .. }) => ("CONFIG_RETIRED_FIELD", error.to_string()),
        _ if error.is::<pathchord_policy::CompileError>() => {
            ("CONFIG_COMPILE_ERROR", error.to_string())
        }
        _ => ("CONFIG_VALIDATION_FAILED", error.to_string()),
    }
}

fn validate(
    role: Role,
    source: &ConfigurationSource,
    documents: &[String],
) -> Result<Option<PolicyConfig>> {
    let inputs = documents.iter().map(String::as_str);
    let base = source.base_directory();
    match role {
        Role::Ingress => {
            let policy =
                KubeConfig::from_documents(inputs)?.into_validated_snapshot(Generation::new(1))?;
            if let Some(settings) = &policy.config().ingress_service {
                validate_private_paths(
                    source,
                    [
                        ("identity", settings.identity.as_deref()),
                        ("dataDir", settings.data_dir.as_deref()),
                        ("credentialsDir", settings.credentials_dir.as_deref()),
                        (
                            "web.tokenFile",
                            settings
                                .web
                                .as_ref()
                                .and_then(|web| web.token_file.as_deref()),
                        ),
                    ],
                )?;
            }
            CompiledPolicy::compile_with_source(&policy, Some(base))?;
            Ok(Some(policy.config().clone()))
        }
        Role::Egress => {
            let spec = pathchord_config::parse_egress_service_documents(inputs)?.spec;
            validate_private_paths(
                source,
                [
                    ("identity", spec.identity.as_deref()),
                    ("authorizationDb", spec.authorization_db.as_deref()),
                    (
                        "web.tokenFile",
                        spec.web.as_ref().and_then(|web| web.token_file.as_deref()),
                    ),
                ],
            )?;
            Ok(None)
        }
    }
}

fn validate_private_paths<const N: usize>(
    source: &ConfigurationSource,
    paths: [(&'static str, Option<&Path>); N],
) -> Result<()> {
    for (field, path) in paths {
        if let Some(path) = path {
            source.validate_private_path(field, &source.base_directory().join(path))?;
        }
    }
    Ok(())
}

fn paths(
    role: Role,
    layout: &RoleLayout,
    selection: &SelectedSource,
    source: &ConfigurationSource,
    loaded: &ConfigurationDocuments,
    socket_override: Option<&Path>,
) -> Result<Value> {
    let base = source.base_directory();
    let report = |configured: Option<&Path>, default: &Path| {
        let path = RoleLayout::resolve_path(base, configured, default);
        let permissions = std::fs::symlink_metadata(&path).ok().map(|metadata| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                format!("{:04o}", metadata.permissions().mode() & 0o7777)
            }
            #[cfg(not(unix))]
            {
                if metadata.permissions().readonly() {
                    "read-only"
                } else {
                    "writable"
                }
                .to_owned()
            }
        });
        json!({"path": path, "origin": if configured.is_some() {"resource"} else {"role default"}, "permissions": permissions})
    };
    let mut result = json!({
        "role": role.name(), "source": source.path(), "source_origin": format!("{:?}", selection.origin), "base": base,
    });
    let configured_socket = match role {
        Role::Ingress => {
            let policy = validate(role, source, &loaded.documents)?.expect("Ingress policy");
            let settings = policy.ingress_service.unwrap_or_default();
            result["identity"] = report(settings.identity.as_deref(), &layout.identity);
            result["state"] = report(settings.data_dir.as_deref(), &layout.state);
            result["credentials"] =
                report(settings.credentials_dir.as_deref(), &layout.credentials);
            if let Some(token) = settings.web.and_then(|web| web.token_file) {
                result["web_token"] = report(Some(&token), Path::new(""));
            }
            settings.control_socket
        }
        Role::Egress => {
            let service = pathchord_config::parse_egress_service_documents(
                loaded.documents.iter().map(String::as_str),
            )?;
            result["identity"] = report(service.spec.identity.as_deref(), &layout.identity);
            result["authorization_db"] = report(
                service.spec.authorization_db.as_deref(),
                &layout.authorization_db,
            );
            result["state"] = report(None, &layout.state);
            result["egress_id"] = json!(service.spec.egress_id.unwrap_or(service.name));
            if let Some(token) = service.spec.web.and_then(|web| web.token_file) {
                result["web_token"] = report(Some(&token), Path::new(""));
            }
            service.spec.control_socket
        }
    };
    result["control_socket"] = if let Some(socket) = socket_override {
        let mut value = report(None, socket);
        value["origin"] = json!("command line");
        value
    } else {
        report(configured_socket.as_deref(), &layout.socket)
    };
    Ok(result)
}

async fn init(
    role: Role,
    layout: &RoleLayout,
    selection: &SelectedSource,
    generate: bool,
) -> Result<Value> {
    if !selection.directory_required && !selection.path.is_dir() {
        return Err("config init requires a directory source; use --config-dir".into());
    }
    let template = match role {
        Role::Ingress => include_str!("../../../examples/ingress-direct.yaml"),
        Role::Egress => {
            "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: egress}\nspec: {bind: '0.0.0.0:7443'}\n"
        }
    };
    if let Some(parent) = layout.socket.parent().filter(|_| !cfg!(windows)) {
        create_directory(parent)?;
    }
    create_directory(&layout.state)?;
    if role == Role::Ingress {
        create_directory(&layout.credentials)?;
    }
    create_directory(&selection.path)?;
    let source = selection.bind().await?;
    let transaction = SourceTransaction::begin(source.path().to_owned()).await?;
    if load_for_edit(&source).await?.files.is_empty() {
        validate(role, &source, &[template.to_owned()])?;
        transaction.commit(&[ResourceChange {
            path: MANAGED.into(),
            before: None,
            after: template.to_owned(),
        }])?;
    }
    drop(transaction);
    if !layout.identity.try_exists()?
        && (generate || confirm("Generate the default local identity?")?)
    {
        write_identity(&layout.identity, &generate_static_keypair()?)?;
    }
    Ok(
        json!({"role": role.name(), "source": selection.path, "identity": layout.identity, "identity_present": layout.identity.try_exists()?}),
    )
}

fn create_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

async fn edit(
    role: Role,
    source: &ConfigurationSource,
    command: ConfigCommand,
    output: Output,
) -> Result<()> {
    if !source.is_directory() {
        return Err("resource edits require a configuration directory; migrate the single-file source to a directory first".into());
    }
    let before = match source.load().await {
        Ok(loaded) => loaded,
        Err(ConfigurationError::EmptyDirectory) => empty_documents(),
        Err(error) => return Err(error.into()),
    };
    let managed_path = source.path().join(MANAGED);
    let managed_before = before
        .files
        .iter()
        .position(|file| *file == managed_path)
        .map(|index| before.documents[index].clone());
    let mut managed = resources(managed_before.as_deref().unwrap_or_default())?;
    let mut extra = None;
    let dry_run = match command {
        ConfigCommand::Create { file, dry_run } => {
            managed.extend(resources(&read_manifest(&file)?)?);
            dry_run
        }
        ConfigCommand::Patch {
            selector,
            file,
            dry_run,
        } => {
            let resource = managed
                .iter_mut()
                .find(|resource| selector.matches(resource))
                .ok_or("managed resource not found; adopt a hand-authored resource first")?;
            let patch: Value = serde_yaml::from_str(&read_manifest(&file)?)?;
            if !patch.is_object() {
                return Err("the patch must be a YAML mapping".into());
            }
            merge_patch(resource, patch);
            if !selector.matches(resource) {
                return Err("a patch must preserve resource identity".into());
            }
            dry_run
        }
        ConfigCommand::Delete { selector, dry_run } => {
            let index = managed
                .iter()
                .position(|resource| selector.matches(resource))
                .ok_or("managed resource not found; adopt a hand-authored resource first")?;
            managed.remove(index);
            dry_run
        }
        ConfigCommand::Adopt {
            resource,
            namespace,
            all_from,
        } => {
            let selector = resource.map(|resource| Selector {
                resource,
                namespace,
            });
            let selected_file = if let Some(file) = all_from {
                let file = if file.is_absolute() {
                    file
                } else {
                    source.path().join(file)
                };
                Some(file.canonicalize()?)
            } else {
                None
            };
            for (file, text) in before.files.iter().zip(&before.documents) {
                if *file == managed_path || selected_file.as_ref().is_some_and(|path| path != file)
                {
                    continue;
                }
                if !file
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| {
                        extension.eq_ignore_ascii_case("yaml")
                            || extension.eq_ignore_ascii_case("yml")
                    })
                {
                    continue;
                }
                let (adopted, remaining) = adopt(text, selector.as_ref())?;
                if adopted.is_empty() {
                    continue;
                }
                if extra.is_some() {
                    return Err("resource identity occurs in more than one source file".into());
                }
                for resource in &adopted {
                    eprintln!(
                        "Move {:?}/{:?} from {} to {MANAGED}",
                        resource["kind"],
                        resource["metadata"]["name"],
                        file.display()
                    );
                }
                managed.extend(adopted);
                extra = Some(ResourceChange {
                    path: file.strip_prefix(source.path())?.to_owned(),
                    before: Some(text.clone()),
                    after: remaining,
                });
            }
            if extra.is_none() {
                return Err("no hand-authored YAML resources matched the adoption request".into());
            }
            false
        }
        _ => unreachable!("mutating configuration command"),
    };
    let mut changes = vec![ResourceChange {
        path: MANAGED.into(),
        before: managed_before,
        after: serialize(&managed)?,
    }];
    if let Some(change) = extra {
        changes.push(change);
    }
    let original = validate(role, source, &before.documents).ok().flatten();
    let mut candidate = before.documents.clone();
    for change in &changes {
        let path = source.path().join(&change.path);
        if let Some(index) = before.files.iter().position(|file| *file == path) {
            candidate[index] = change.after.clone();
        } else {
            candidate.push(change.after.clone());
        }
    }
    let total = candidate.iter().map(String::len).sum::<usize>();
    if candidate.len() > pathchord_config::MAX_CONFIGURATION_FILES
        || total as u64 > pathchord_config::MAX_CONFIGURATION_BYTES
    {
        return Err("candidate exceeds configuration source limits".into());
    }
    let next = validate(role, source, &candidate)?;
    if changes.len() > 1
        && (!confirm("Candidate validated. Proceed with adoption?")?
            || !confirm("Remove the previewed resources from the source YAML?")?)
    {
        return Err("adoption cancelled".into());
    }
    if !dry_run {
        let transaction = SourceTransaction::begin(source.path().to_owned()).await?;
        let current = load_for_edit(source).await?;
        if current.files != before.files || current.documents != before.documents {
            return Err("configuration changed during editing; run the command again".into());
        }
        validate(role, source, &candidate)?;
        transaction.commit(&changes)?;
    }
    let activation = match (original, next) {
        (Some(original), Some(next)) if original == next => "configuration unchanged",
        (Some(original), Some(next))
            if original.ingress_service == next.ingress_service
                && original.egresses == next.egresses
                && original.listeners == next.listeners
                && original.dns_policy == next.dns_policy =>
        {
            "eligible for reload"
        }
        _ => "restart required",
    };
    print(
        output,
        &json!({"written": !dry_run, "path": managed_path, "activation": activation}),
    )
}

async fn load_for_edit(source: &ConfigurationSource) -> Result<ConfigurationDocuments> {
    match source.load_unlocked().await {
        Ok(loaded) => Ok(loaded),
        Err(ConfigurationError::EmptyDirectory) => Ok(empty_documents()),
        Err(error) => Err(error.into()),
    }
}

fn empty_documents() -> ConfigurationDocuments {
    ConfigurationDocuments {
        documents: Vec::new(),
        directories: Default::default(),
        files: Vec::new(),
    }
}

fn read_manifest(path: &Path) -> Result<String> {
    let input: Box<dyn Read> = if path == Path::new("-") {
        Box::new(std::io::stdin().lock())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut text = String::new();
    input
        .take(pathchord_config::MAX_CONFIGURATION_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > pathchord_config::MAX_CONFIGURATION_BYTES {
        return Err("manifest exceeds size bound".into());
    }
    Ok(text)
}

fn resources(text: &str) -> Result<Vec<Value>> {
    let mut resources = Vec::new();
    for doc in serde_yaml::from_str_multi::<Value>(text)? {
        if doc.is_null() {
            continue;
        }
        if doc["kind"] == "List" {
            resources.extend(
                doc["items"]
                    .as_array()
                    .ok_or("List requires items")?
                    .iter()
                    .cloned(),
            );
        } else {
            resources.push(doc);
        }
    }
    Ok(resources)
}

fn serialize(resources: &[Value]) -> Result<String> {
    Ok(serde_yaml::to_string(
        &json!({"apiVersion": "pathchord.io/v1", "kind": "List", "metadata": {"name": "managed"}, "items": resources}),
    )?)
}

fn adopt(text: &str, selector: Option<&Selector>) -> Result<(Vec<Value>, String)> {
    let mut adopted = Vec::new();
    let mut remaining = String::new();
    for mut document in noyalib::cst::parse_stream(text)? {
        let values = resources(document.source())?;
        let matches = values
            .iter()
            .enumerate()
            .filter(|(_, value)| selector.is_none_or(|selector| selector.matches(value)))
            .collect::<Vec<_>>();
        if matches.is_empty() {
            remaining.push_str(document.source());
            continue;
        }
        for (_, value) in &matches {
            adopted.push((*value).clone());
        }
        if matches.len() == values.len() {
            for line in document.source().split_inclusive('\n') {
                if line.trim_start().starts_with('#') {
                    remaining.push_str(line);
                }
            }
            continue;
        }
        for (index, _) in matches.into_iter().rev() {
            document.remove(&format!("items[{index}]"))?;
        }
        remaining.push_str(document.source());
    }
    Ok((adopted, remaining))
}

fn merge_patch(resource: &mut Value, patch: Value) {
    if let Value::Object(patch) = patch {
        if !resource.is_object() {
            *resource = json!({});
        }
        let fields = resource.as_object_mut().expect("mapping");
        for (key, value) in patch {
            if value.is_null() {
                fields.remove(&key);
            } else {
                merge_patch(fields.entry(key).or_insert(Value::Null), value);
            }
        }
    } else {
        *resource = patch;
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(false);
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let key = key.to_ascii_lowercase();
                if [
                    "password",
                    "secret",
                    "token",
                    "privatekey",
                    "authorization",
                    "cookie",
                ]
                .iter()
                .any(|secret| key.contains(secret))
                    || matches!(key.as_str(), "url" | "headers")
                {
                    *value = json!("[redacted]");
                } else {
                    redact(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact),
        _ => {}
    }
}

fn print(output: Output, value: &Value) -> Result<()> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Yaml => print!("{}", serde_yaml::to_string(value)?),
        Output::Human => print_fields(value, 0),
    }
    Ok(())
}

fn print_fields(value: &Value, indent: usize) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if value.is_object() || value.is_array() {
                    println!("{:indent$}{}:", "", super::display_value(Some(&json!(key))));
                    print_fields(value, indent + 2);
                } else {
                    println!(
                        "{:indent$}{}: {}",
                        "",
                        super::display_value(Some(&json!(key))),
                        super::display_value(Some(value))
                    );
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                if value.is_object() || value.is_array() {
                    println!("{:indent$}-", "");
                    print_fields(value, indent + 2);
                } else {
                    println!("{:indent$}- {}", "", super::display_value(Some(value)));
                }
            }
        }
        _ => println!("{:indent$}{}", "", super::display_value(Some(value))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initialization_preserves_the_identity_and_manifest_on_reentry() {
        let root =
            std::env::temp_dir().join(format!("pc-init-{}", super::super::request_id().unwrap()));
        let state = root.join("state");
        let configuration = root.join("config");
        let layout = RoleLayout {
            configuration: configuration.clone(),
            state: state.clone(),
            socket: root.join("runtime/egress.sock"),
            identity: state.join("identity.key"),
            credentials: state.join("credentials"),
            authorization_db: state.join("auth.db"),
            socket_candidates: Vec::new(),
        };
        let selected = SelectedSource {
            path: configuration.clone(),
            directory_required: true,
            origin: pathchord_config::SourceOrigin::CommandLine,
        };
        init(Role::Egress, &layout, &selected, true).await.unwrap();
        let key = std::fs::read(&layout.identity).unwrap();
        let manifest = configuration.join(MANAGED);
        let authored = std::fs::read_to_string(&manifest).unwrap() + "# operator change\n";
        std::fs::write(&manifest, &authored).unwrap();
        init(Role::Egress, &layout, &selected, true).await.unwrap();
        assert_eq!(std::fs::read(layout.identity).unwrap(), key);
        assert_eq!(std::fs::read_to_string(manifest).unwrap(), authored);
        assert!(!layout.authorization_db.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn adopts_one_list_item_and_preserves_unrelated_comments() {
        let source = "# bundle\napiVersion: pathchord.io/v1\nkind: List\nmetadata: {name: test}\nitems:\n  - apiVersion: pathchord.io/v1\n    kind: EgressService\n    metadata: {name: moved}\n    spec: {}\n  # Keep this comment.\n  - apiVersion: pathchord.io/v1\n    kind: EgressService\n    metadata: {name: retained}\n    spec: {}\n";
        let selector = Selector {
            resource: "egressservice/moved".into(),
            namespace: "default".into(),
        };
        let (adopted, remaining) = adopt(source, Some(&selector)).unwrap();
        assert_eq!(adopted.len(), 1);
        assert_eq!(
            resources(&remaining).unwrap()[0]["metadata"]["name"],
            "retained"
        );
        assert!(remaining.contains("# Keep this comment."));
        assert!(remaining.contains("# bundle"));
    }

    #[test]
    fn adopts_one_document_and_leaves_comment_only_source() {
        let source = "# Service configuration\napiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: edge}\nspec: {}\n";
        let (adopted, remaining) = adopt(source, None).unwrap();
        assert_eq!(adopted.len(), 1);
        assert_eq!(remaining, "# Service configuration\n");
    }
}
