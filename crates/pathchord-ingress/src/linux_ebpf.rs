//! Linux TC eBPF interception backend.
//!
//! The first backend is deliberately small: it attaches an ingress classifier
//! to one administrator-selected interface and marks TCP/UDP packets so the
//! existing PathChord transparent listener and policy route receive them. The
//! userspace listener, original-destination handling, UDP associations, and
//! Path/Session data plane remain unchanged.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

use thiserror::Error;

static EBPF_OBJECT: &[u8] = include_bytes!(env!("PATHCHORD_EBPF_OBJECT"));

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LinuxEbpfError {
    #[error("Linux eBPF backend configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("Linux eBPF object is unavailable: {0}")]
    Unavailable(String),
    #[error("Linux eBPF command failed: {0}")]
    Command(String),
    #[error("Linux eBPF cleanup failed: {0}")]
    Cleanup(String),
    #[error("Linux eBPF ownership conflicts with an existing TC filter or pin directory")]
    OwnershipConflict,
}

#[derive(Debug)]
pub struct LinuxEbpfInterception {
    interface: String,
    priority: u16,
    pin_dir: PathBuf,
    clsact_owned: bool,
    program_id: Option<u32>,
    pin_owned: bool,
    journal_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackendJournal {
    interface: String,
    priority: u16,
    program_id: u32,
    clsact_owned: bool,
}

impl LinuxEbpfInterception {
    pub fn attach(
        data_dir: &Path,
        listener_id: &str,
        interface: &str,
        mark: u32,
        priority: u32,
    ) -> Result<Self, LinuxEbpfError> {
        validate_interface(interface)?;
        if mark == 0 {
            return Err(LinuxEbpfError::InvalidConfig(
                "eBPF mark must be non-zero".to_owned(),
            ));
        }
        let priority = u16::try_from(priority).map_err(|_| {
            LinuxEbpfError::InvalidConfig("eBPF TC priority must fit u16".to_owned())
        })?;
        if priority == 0 {
            return Err(LinuxEbpfError::InvalidConfig(
                "eBPF TC priority must be non-zero".to_owned(),
            ));
        }
        if EBPF_OBJECT.is_empty() {
            return Err(LinuxEbpfError::Unavailable(
                "the eBPF object was not generated; install clang and rebuild PathChord".to_owned(),
            ));
        }
        let identity = pathchord_policy::ResourceIdentity::from_id(listener_id);
        let safe_id = if identity.namespace == pathchord_policy::ResourceIdentity::DEFAULT_NAMESPACE
        {
            listener_id.replace(|character: char| !character.is_ascii_alphanumeric(), "_")
        } else {
            identity.storage_component()
        };
        let object_dir = data_dir.join("ebpf").join(&safe_id);
        std::fs::create_dir_all(&object_dir).map_err(|error| {
            LinuxEbpfError::Command(format!("create object directory: {error}"))
        })?;
        // BPF pins require bpffs; ordinary data directories cannot hold them.
        // Conversely bpffs cannot hold the ELF object or the durable journal.
        let canonical_data = std::fs::canonicalize(data_dir)
            .map_err(|error| LinuxEbpfError::Command(error.to_string()))?;
        let digest = orion::hazardous::hash::sha2::sha256::Sha256::digest(
            canonical_data.as_os_str().as_encoded_bytes(),
        )
        .map_err(|error| LinuxEbpfError::Command(error.to_string()))?;
        let owner = digest.as_ref()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let pin_dir = PathBuf::from("/sys/fs/bpf/pathchord")
            .join(owner)
            .join(safe_id);
        let journal_path = object_dir.join("owner.json");
        let mut backend = Self {
            interface: interface.to_owned(),
            priority,
            pin_dir,
            clsact_owned: false,
            program_id: None,
            pin_owned: false,
            journal_path,
        };
        if backend.journal_path.exists() {
            let encoded = std::fs::read(&backend.journal_path)
                .map_err(|error| LinuxEbpfError::Cleanup(error.to_string()))?;
            let journal: BackendJournal = serde_json::from_slice(&encoded)
                .map_err(|error| LinuxEbpfError::Cleanup(error.to_string()))?;
            let mut old = Self {
                interface: journal.interface,
                priority: journal.priority,
                pin_dir: backend.pin_dir.clone(),
                clsact_owned: journal.clsact_owned,
                program_id: Some(journal.program_id),
                pin_owned: true,
                journal_path: backend.journal_path.clone(),
            };
            old.detach()?;
        }
        // Never add beside or delete a filter from an administrator's slot.
        if !backend.filters(Some(priority), "ingress")?.is_empty() {
            return Err(LinuxEbpfError::OwnershipConflict);
        }
        let object_path = object_dir.join("pathchord_tproxy.o");
        std::fs::write(&object_path, EBPF_OBJECT)
            .map_err(|error| LinuxEbpfError::Command(format!("write eBPF object: {error}")))?;
        std::fs::create_dir_all(backend.pin_dir.parent().expect("BPF pin parent"))
            .map_err(|error| LinuxEbpfError::Unavailable(format!("bpffs pin root: {error}")))?;
        std::fs::create_dir(&backend.pin_dir).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                LinuxEbpfError::OwnershipConflict
            } else {
                LinuxEbpfError::Unavailable(format!("bpffs pin directory: {error}"))
            }
        })?;
        backend.pin_owned = true;
        if let Err(error) = backend.load_and_attach(&object_path, mark) {
            let _ = backend.detach();
            return Err(error);
        }
        Ok(backend)
    }

    fn load_and_attach(&mut self, object: &Path, mark: u32) -> Result<(), LinuxEbpfError> {
        let pin_dir = path_text(&self.pin_dir)?;
        run_command(
            "bpftool",
            [
                "prog",
                "loadall",
                path_text(object)?,
                pin_dir,
                "type",
                "classifier",
                "pinmaps",
                pin_dir,
            ],
        )?;
        let program_path = self.pin_dir.join("pathchord_tproxy");
        let program = query_json(
            "bpftool",
            &[
                "--json",
                "prog",
                "show",
                "pinned",
                path_text(&program_path)?,
            ],
        )?;
        let program = program
            .as_array()
            .and_then(|items| items.first())
            .unwrap_or(&program);
        self.program_id = program
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok());
        if self.program_id.is_none() {
            return Err(LinuxEbpfError::Command(
                "loaded BPF program has no ID".to_owned(),
            ));
        }
        self.write_journal()?;
        let map_path = self.pin_dir.join("pathchord_config_map");
        let mark_bytes = mark.to_le_bytes();
        let mark_hex = mark_bytes.map(|byte| format!("{byte:02x}"));
        let mut map_args = vec![
            "map",
            "update",
            "pinned",
            path_text(&map_path)?,
            "key",
            "hex",
        ];
        map_args.extend(["00", "00", "00", "00"]);
        map_args.push("value");
        map_args.push("hex");
        map_args.extend(mark_hex.iter().map(String::as_str));
        map_args.push("any");
        run_command("bpftool", map_args)?;
        // Existing clsact is shared administrator state. Inspect its kind
        // instead of depending on localized EEXIST wording from tc/netlink.
        let qdiscs = query_json("tc", &["-json", "qdisc", "show", "dev", &self.interface])?;
        let qdiscs = qdiscs
            .as_array()
            .ok_or_else(|| LinuxEbpfError::Command("invalid TC qdisc inventory".to_owned()))?;
        if !qdiscs
            .iter()
            .any(|qdisc| qdisc.get("kind").and_then(Value::as_str) == Some("clsact"))
        {
            run_command("tc", ["qdisc", "add", "dev", &self.interface, "clsact"])?;
            self.clsact_owned = true;
        }
        self.write_journal()?;
        let priority = self.priority.to_string();
        run_command(
            "tc",
            [
                "filter",
                "add",
                "dev",
                &self.interface,
                "ingress",
                "pref",
                &priority,
                "handle",
                "1",
                "bpf",
                "da",
                "pinned",
                path_text(&program_path)?,
            ],
        )?;
        Ok(())
    }

    fn filters(
        &self,
        priority: Option<u16>,
        direction: &str,
    ) -> Result<Vec<Value>, LinuxEbpfError> {
        let mut arguments = vec![
            "-json".to_owned(),
            "filter".to_owned(),
            "show".to_owned(),
            "dev".to_owned(),
            self.interface.clone(),
            direction.to_owned(),
        ];
        if let Some(priority) = priority {
            arguments.extend(["pref".to_owned(), priority.to_string()]);
        }
        let references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let value = query_json("tc", &references)?;
        value
            .as_array()
            .cloned()
            .ok_or_else(|| LinuxEbpfError::Command("invalid TC filter inventory".to_owned()))
    }

    fn write_journal(&self) -> Result<(), LinuxEbpfError> {
        let journal = BackendJournal {
            interface: self.interface.clone(),
            priority: self.priority,
            program_id: self.program_id.expect("loaded BPF program"),
            clsact_owned: self.clsact_owned,
        };
        let mut options = atomic_write_file::OpenOptions::new();
        use atomic_write_file::unix::OpenOptionsExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        options.preserve_mode(false).mode(0o600);
        let mut file = options
            .open(&self.journal_path)
            .map_err(|error| LinuxEbpfError::Command(error.to_string()))?;
        let encoded = serde_json::to_vec(&journal)
            .map_err(|error| LinuxEbpfError::Command(error.to_string()))?;
        file.write_all(&encoded)
            .and_then(|()| file.commit())
            .map_err(|error| LinuxEbpfError::Command(error.to_string()))
    }

    pub fn detach(&mut self) -> Result<(), LinuxEbpfError> {
        if !self.pin_owned {
            return Ok(());
        }
        let mut pinned_program_matches = self.program_id.is_none();
        if let Some(program_id) = self.program_id {
            let pin = self.pin_dir.join("pathchord_tproxy");
            if pin.exists() {
                let pinned = query_json(
                    "bpftool",
                    &["--json", "prog", "show", "pinned", path_text(&pin)?],
                )?;
                let pinned = pinned
                    .as_array()
                    .and_then(|programs| programs.first())
                    .unwrap_or(&pinned);
                pinned_program_matches =
                    pinned.get("id").and_then(Value::as_u64) == Some(u64::from(program_id));
                if !pinned_program_matches {
                    return Err(LinuxEbpfError::OwnershipConflict);
                }
            }
            let filters = self.filters(Some(self.priority), "ingress")?;
            if !filters.is_empty() {
                // A numeric program ID in a durable journal can be reused
                // after reboot. Its live bpffs pin must still identify the
                // program before any same-number TC object is removed.
                if !pinned_program_matches || !owns_filter_inventory(&filters, program_id) {
                    return Err(LinuxEbpfError::OwnershipConflict);
                }
                run_command(
                    "tc",
                    [
                        "filter",
                        "del",
                        "dev",
                        &self.interface,
                        "ingress",
                        "pref",
                        &self.priority.to_string(),
                        "handle",
                        "1",
                        "bpf",
                    ],
                )?;
            }
        }
        // A foreign filter added after startup must keep its shared clsact.
        if self.clsact_owned
            && pinned_program_matches
            && self.filters(None, "ingress")?.is_empty()
            && self.filters(None, "egress")?.is_empty()
        {
            run_command_allow_missing("tc", ["qdisc", "del", "dev", &self.interface, "clsact"])?;
        }
        std::fs::remove_dir_all(&self.pin_dir)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| LinuxEbpfError::Cleanup(error.to_string()))?;
        if let Some(parent) = self.pin_dir.parent() {
            // Remove only our now-empty owner directory; the shared root remains.
            let _ = std::fs::remove_dir(parent);
        }
        match std::fs::remove_file(&self.journal_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(LinuxEbpfError::Cleanup(error.to_string())),
        }
        self.program_id = None;
        self.pin_owned = false;
        self.clsact_owned = false;
        Ok(())
    }
}

impl Drop for LinuxEbpfInterception {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

fn owns_filter_inventory(filters: &[Value], program_id: u32) -> bool {
    // TC emits a protocol/chain header plus the concrete filter. Recent
    // iproute2 nests the program ID under options.prog; older releases put it
    // directly under options. A header is not a second filter instance.
    let mut instances = 0;
    let matching = filters.iter().all(|filter| {
        if filter.get("kind").and_then(Value::as_str) != Some("bpf")
            || filter.get("protocol").and_then(Value::as_str) != Some("all")
            || filter
                .get("chain")
                .is_some_and(|chain| chain.as_u64() != Some(0))
        {
            return false;
        }
        let Some(options) = filter.get("options") else {
            return true;
        };
        instances += 1;
        let id = options
            .get("prog")
            .and_then(|program| program.get("id"))
            .or_else(|| options.get("id"));
        id.and_then(Value::as_u64) == Some(u64::from(program_id))
            && matches!(
                options.get("handle").and_then(Value::as_str),
                Some("0x1" | "1")
            )
            && options.get("direct-action").and_then(Value::as_bool) == Some(true)
    });
    matching && instances == 1
}

fn path_text(path: &Path) -> Result<&str, LinuxEbpfError> {
    path.to_str()
        .ok_or_else(|| LinuxEbpfError::InvalidConfig("eBPF path is not UTF-8".to_owned()))
}

fn query_json(program: &str, arguments: &[&str]) -> Result<Value, LinuxEbpfError> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| LinuxEbpfError::Unavailable(format!("{program}: {error}")))?;
    if !output.status.success() {
        return Err(LinuxEbpfError::Command(format_command_error(
            program, &output,
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| LinuxEbpfError::Command(error.to_string()))
}

fn validate_interface(interface: &str) -> Result<(), LinuxEbpfError> {
    if interface.is_empty() || interface.len() > 15 || interface.chars().any(char::is_control) {
        return Err(LinuxEbpfError::InvalidConfig(
            "eBPF interface must be 1..=15 non-control characters".to_owned(),
        ));
    }
    Ok(())
}

fn run_command<I, S>(program: &str, arguments: I) -> Result<(), LinuxEbpfError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| LinuxEbpfError::Unavailable(format!("{program}: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxEbpfError::Command(format_command_error(
            program, &output,
        )))
    }
}

fn run_command_allow_missing<I, S>(program: &str, arguments: I) -> Result<(), LinuxEbpfError>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<std::ffi::OsStr>,
{
    match run_command(program, arguments) {
        Ok(()) => Ok(()),
        Err(LinuxEbpfError::Command(message))
            if message.to_ascii_lowercase().contains("cannot find")
                || message.to_ascii_lowercase().contains("no such file")
                || message.to_ascii_lowercase().contains("not found") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn format_command_error(program: &str, output: &std::process::Output) -> String {
    // bpftool --json puts structured failures on stdout, including pin errors.
    let diagnostic = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    format!(
        "{program} ({}): {}",
        output.status,
        String::from_utf8_lossy(diagnostic).trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_inventory_headers_and_nested_program_ids_preserve_filter_ownership() {
        let mut filters = serde_json::json!([
            {"protocol":"all","kind":"bpf","chain":0},
            {"protocol":"all","kind":"bpf","chain":0,"options":{
                "handle":"0x1","direct-action":true,"prog":{"id":6,"name":"pathchord_tprox"}}}
        ])
        .as_array()
        .unwrap()
        .clone();
        assert!(owns_filter_inventory(&filters, 6));
        assert!(!owns_filter_inventory(&filters, 7));
        filters[1]["options"]["prog"]["id"] = serde_json::json!(7);
        assert!(!owns_filter_inventory(&filters, 6));
        filters[1]["options"]
            .as_object_mut()
            .unwrap()
            .remove("prog");
        filters[1]["options"]["id"] = serde_json::json!(6);
        assert!(owns_filter_inventory(&filters, 6));
        filters.push(serde_json::json!({"kind":"matchall","protocol":"all"}));
        assert!(!owns_filter_inventory(&filters, 6));
    }
}
