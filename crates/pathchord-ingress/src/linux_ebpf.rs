//! Linux TC eBPF interception backend.
//!
//! The first backend is deliberately small: it attaches an ingress classifier
//! to one administrator-selected interface and marks TCP/UDP packets so the
//! existing PathChord transparent listener and policy route receive them. The
//! userspace listener, original-destination handling, UDP associations, and
//! Path/Session data plane remain unchanged.

use std::path::{Path, PathBuf};
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
}

#[derive(Debug)]
pub struct LinuxEbpfInterception {
    interface: String,
    priority: u16,
    pin_dir: PathBuf,
    clsact_owned: bool,
    attached: bool,
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
        let safe_id =
            listener_id.replace(|character: char| !character.is_ascii_alphanumeric(), "_");
        let pin_dir = data_dir.join("ebpf").join(safe_id);
        std::fs::create_dir_all(&pin_dir)
            .map_err(|error| LinuxEbpfError::Command(format!("create pin directory: {error}")))?;
        let object_path = pin_dir.join("pathchord_tproxy.o");
        std::fs::write(&object_path, EBPF_OBJECT)
            .map_err(|error| LinuxEbpfError::Command(format!("write eBPF object: {error}")))?;

        let mut backend = Self {
            interface: interface.to_owned(),
            priority,
            pin_dir,
            clsact_owned: false,
            attached: false,
        };
        if let Err(error) = backend.load_and_attach(&object_path, mark) {
            let _ = backend.detach();
            return Err(error);
        }
        Ok(backend)
    }

    fn load_and_attach(&mut self, object: &Path, mark: u32) -> Result<(), LinuxEbpfError> {
        let pin_dir = self.pin_dir.to_str().ok_or_else(|| {
            LinuxEbpfError::InvalidConfig("eBPF pin path is not UTF-8".to_owned())
        })?;
        run_command(
            "bpftool",
            [
                "prog",
                "loadall",
                object.to_str().ok_or_else(|| {
                    LinuxEbpfError::InvalidConfig("eBPF object path is not UTF-8".to_owned())
                })?,
                pin_dir,
                "type",
                "classifier",
                "pinmaps",
                pin_dir,
            ],
        )?;
        let map_path = self.pin_dir.join("pathchord_config_map");
        let map_path = map_path.to_str().ok_or_else(|| {
            LinuxEbpfError::InvalidConfig("eBPF map path is not UTF-8".to_owned())
        })?;
        let mark_bytes = mark.to_le_bytes();
        let mark_hex = mark_bytes.map(|byte| format!("{byte:02x}"));
        let mut map_args = vec!["map", "update", "pinned", map_path, "key", "hex"];
        map_args.extend(["00", "00", "00", "00"]);
        map_args.push("value");
        map_args.push("hex");
        map_args.extend(mark_hex.iter().map(String::as_str));
        map_args.push("any");
        run_command("bpftool", map_args)?;

        let qdisc =
            run_command_allow_existing("tc", ["qdisc", "add", "dev", &self.interface, "clsact"])?;
        self.clsact_owned = qdisc;
        let program_path = self.pin_dir.join("pathchord_tproxy");
        let program_path = program_path.to_str().ok_or_else(|| {
            LinuxEbpfError::InvalidConfig("eBPF program path is not UTF-8".to_owned())
        })?;
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
                "bpf",
                "da",
                "pinned",
                program_path,
            ],
        )?;
        self.attached = true;
        Ok(())
    }

    pub fn detach(&mut self) -> Result<(), LinuxEbpfError> {
        if !self.attached && !self.pin_dir.exists() {
            return Ok(());
        }
        let priority = self.priority.to_string();
        let filter_result = run_command_allow_missing(
            "tc",
            [
                "filter",
                "del",
                "dev",
                &self.interface,
                "ingress",
                "pref",
                &priority,
            ],
        );
        let qdisc_result = if self.clsact_owned {
            run_command_allow_missing("tc", ["qdisc", "del", "dev", &self.interface, "clsact"])
        } else {
            Ok(())
        };
        let pin_result = std::fs::remove_dir_all(&self.pin_dir).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        });
        self.attached = false;
        self.clsact_owned = false;
        filter_result
            .and(qdisc_result)
            .and(pin_result.map_err(|error| LinuxEbpfError::Cleanup(error.to_string())))
            .map_err(|error| match error {
                LinuxEbpfError::Cleanup(_) => error,
                other => LinuxEbpfError::Cleanup(other.to_string()),
            })
    }
}

impl Drop for LinuxEbpfInterception {
    fn drop(&mut self) {
        let _ = self.detach();
    }
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
            program,
            &output.stderr,
        )))
    }
}

fn run_command_allow_existing<I, S>(program: &str, arguments: I) -> Result<bool, LinuxEbpfError>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<std::ffi::OsStr>,
{
    match run_command(program, arguments.clone()) {
        Ok(()) => Ok(true),
        Err(LinuxEbpfError::Command(message))
            if message.to_ascii_lowercase().contains("file exists")
                || message.to_ascii_lowercase().contains("exists") =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
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

fn format_command_error(program: &str, stderr: &[u8]) -> String {
    format!("{program}: {}", String::from_utf8_lossy(stderr).trim())
}
