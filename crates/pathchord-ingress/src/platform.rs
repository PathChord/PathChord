//! Platform integration adapters for system proxy and packet interception.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

#[cfg(windows)]
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::ListenerId;

/// Atomically replaced protected destinations that platform adapters must not
/// feed back into transparent interception.
#[derive(Debug, Clone, Default)]
pub struct ProtectedEndpointSet {
    endpoints: Arc<RwLock<BTreeSet<SocketAddr>>>,
}

impl ProtectedEndpointSet {
    pub fn replace(&self, endpoints: impl IntoIterator<Item = SocketAddr>) {
        *self
            .endpoints
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = endpoints.into_iter().collect();
    }

    #[must_use]
    pub fn contains(&self, endpoint: &SocketAddr) -> bool {
        self.endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(endpoint)
    }

    #[must_use]
    pub fn snapshot(&self) -> BTreeSet<SocketAddr> {
        self.endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformProxyKind {
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformProxyRequest {
    pub listener_id: ListenerId,
    pub kind: PlatformProxyKind,
    pub endpoint: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformProxyEffect {
    pub environment_applied: bool,
    pub operating_system_applied: bool,
    pub restored: bool,
}

impl PlatformProxyEffect {
    pub const fn applied() -> Self {
        Self {
            environment_applied: true,
            operating_system_applied: true,
            restored: false,
        }
    }

    pub const fn restored() -> Self {
        Self {
            environment_applied: false,
            operating_system_applied: false,
            restored: true,
        }
    }

    pub const fn not_required() -> Self {
        Self {
            environment_applied: false,
            operating_system_applied: false,
            restored: false,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlatformProxyError {
    #[error("system proxy is unsupported on this platform")]
    Unsupported,
    #[error("system proxy endpoint must use a loopback address")]
    NonLoopbackEndpoint,
    #[error("system proxy journal is unavailable: {0}")]
    Journal(String),
    #[error("Windows registry operation failed: {0}")]
    Registry(String),
    #[error("Windows proxy refresh failed: {0}")]
    Refresh(String),
    #[error("injected platform proxy failure: {0}")]
    Injected(String),
}

/// Applies and exactly restores one platform proxy transaction.
pub trait PlatformProxyAdapter: std::fmt::Debug + Send + Sync {
    fn recover(&self) -> Result<PlatformProxyEffect, PlatformProxyError>;

    fn apply(
        &self,
        request: &PlatformProxyRequest,
    ) -> Result<PlatformProxyEffect, PlatformProxyError>;

    fn restore(&self) -> Result<PlatformProxyEffect, PlatformProxyError>;
}

#[derive(Debug, Default)]
struct FakePlatformProxyState {
    applied: Option<PlatformProxyRequest>,
    fail_next: Option<String>,
}

/// Deterministic adapter used by platform-independent control tests.
#[derive(Debug, Default)]
pub struct FakePlatformProxyAdapter {
    state: Mutex<FakePlatformProxyState>,
}

impl FakePlatformProxyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_next(&self, message: impl Into<String>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_next = Some(message.into());
    }

    #[must_use]
    pub fn applied(&self) -> Option<PlatformProxyRequest> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .applied
            .clone()
    }

    fn failure(state: &mut FakePlatformProxyState) -> Result<(), PlatformProxyError> {
        match state.fail_next.take() {
            Some(message) => Err(PlatformProxyError::Injected(message)),
            None => Ok(()),
        }
    }
}

impl PlatformProxyAdapter for FakePlatformProxyAdapter {
    fn recover(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PlatformProxyError::Injected("fake adapter lock poisoned".to_owned()))?;
        Self::failure(&mut state)?;
        if state.applied.take().is_some() {
            Ok(PlatformProxyEffect::restored())
        } else {
            Ok(PlatformProxyEffect::not_required())
        }
    }

    fn apply(
        &self,
        request: &PlatformProxyRequest,
    ) -> Result<PlatformProxyEffect, PlatformProxyError> {
        if !request.endpoint.ip().is_loopback() {
            return Err(PlatformProxyError::NonLoopbackEndpoint);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| PlatformProxyError::Injected("fake adapter lock poisoned".to_owned()))?;
        Self::failure(&mut state)?;
        state.applied = Some(request.clone());
        Ok(PlatformProxyEffect::applied())
    }

    fn restore(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        self.recover()
    }
}

#[derive(Debug, Default)]
pub struct UnsupportedPlatformProxyAdapter;

impl PlatformProxyAdapter for UnsupportedPlatformProxyAdapter {
    fn recover(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        Ok(PlatformProxyEffect::not_required())
    }

    fn apply(
        &self,
        _request: &PlatformProxyRequest,
    ) -> Result<PlatformProxyEffect, PlatformProxyError> {
        Err(PlatformProxyError::Unsupported)
    }

    fn restore(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        Err(PlatformProxyError::Unsupported)
    }
}

#[cfg(windows)]
const ENVIRONMENT_KEY: &str = "Environment";
#[cfg(windows)]
const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
#[cfg(windows)]
const ENVIRONMENT_VALUES: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
#[cfg(windows)]
const INTERNET_VALUES: [&str; 3] = ["ProxyEnable", "ProxyServer", "ProxyOverride"];

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SavedRegistryValue {
    registry_type: u32,
    bytes: Vec<u8>,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegistryJournal {
    environment: Vec<(String, Option<SavedRegistryValue>)>,
    internet_settings: Vec<(String, Option<SavedRegistryValue>)>,
}

/// Safe Windows registry implementation with an atomic crash-recovery journal.
#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsSystemProxyAdapter {
    journal_path: PathBuf,
    operation_lock: Mutex<()>,
}

#[cfg(windows)]
impl WindowsSystemProxyAdapter {
    #[must_use]
    pub fn new(journal_path: impl Into<PathBuf>) -> Self {
        Self {
            journal_path: journal_path.into(),
            operation_lock: Mutex::new(()),
        }
    }

    #[must_use]
    pub fn default_journal_path() -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("PathChord")
            .join("system-proxy-journal.json")
    }

    fn capture(&self) -> Result<RegistryJournal, PlatformProxyError> {
        let environment = windows_registry::CURRENT_USER
            .create(ENVIRONMENT_KEY)
            .map_err(registry_error)?;
        let internet = windows_registry::CURRENT_USER
            .create(INTERNET_SETTINGS_KEY)
            .map_err(registry_error)?;
        Ok(RegistryJournal {
            environment: ENVIRONMENT_VALUES
                .into_iter()
                .map(|name| Ok((name.to_owned(), read_registry_value(&environment, name)?)))
                .collect::<Result<_, PlatformProxyError>>()?,
            internet_settings: INTERNET_VALUES
                .into_iter()
                .map(|name| Ok((name.to_owned(), read_registry_value(&internet, name)?)))
                .collect::<Result<_, PlatformProxyError>>()?,
        })
    }

    fn apply_registry(&self, request: &PlatformProxyRequest) -> Result<(), PlatformProxyError> {
        let environment = windows_registry::CURRENT_USER
            .create(ENVIRONMENT_KEY)
            .map_err(registry_error)?;
        let internet = windows_registry::CURRENT_USER
            .create(INTERNET_SETTINGS_KEY)
            .map_err(registry_error)?;
        let authority = socket_authority(request.endpoint);
        let proxy_url = match request.kind {
            PlatformProxyKind::Http => format!("http://{authority}"),
            PlatformProxyKind::Socks5 => format!("socks5://{authority}"),
        };
        for name in ENVIRONMENT_VALUES {
            environment
                .set_string(name, &proxy_url)
                .map_err(registry_error)?;
        }
        let proxy_server = match request.kind {
            PlatformProxyKind::Http => format!("http={authority};https={authority}"),
            PlatformProxyKind::Socks5 => format!("socks={authority}"),
        };
        internet.set_u32("ProxyEnable", 1).map_err(registry_error)?;
        internet
            .set_string("ProxyServer", &proxy_server)
            .map_err(registry_error)?;
        internet
            .set_string("ProxyOverride", "<local>")
            .map_err(registry_error)?;
        refresh_windows_proxy()?;
        Ok(())
    }

    fn restore_journal(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        if !self.journal_path.exists() {
            return Ok(PlatformProxyEffect::not_required());
        }
        let encoded = std::fs::read(&self.journal_path)
            .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
        let journal: RegistryJournal = serde_json::from_slice(&encoded)
            .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
        let environment = windows_registry::CURRENT_USER
            .create(ENVIRONMENT_KEY)
            .map_err(registry_error)?;
        let internet = windows_registry::CURRENT_USER
            .create(INTERNET_SETTINGS_KEY)
            .map_err(registry_error)?;
        restore_values(&environment, journal.environment)?;
        restore_values(&internet, journal.internet_settings)?;
        refresh_windows_proxy()?;
        std::fs::remove_file(&self.journal_path)
            .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
        Ok(PlatformProxyEffect::restored())
    }
}

#[cfg(windows)]
impl Default for WindowsSystemProxyAdapter {
    fn default() -> Self {
        Self::new(Self::default_journal_path())
    }
}

#[cfg(windows)]
impl Drop for WindowsSystemProxyAdapter {
    fn drop(&mut self) {
        if let Ok(_guard) = self.operation_lock.lock() {
            let _ = self.restore_journal();
        }
    }
}

#[cfg(windows)]
impl PlatformProxyAdapter for WindowsSystemProxyAdapter {
    fn recover(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| PlatformProxyError::Journal("operation lock poisoned".to_owned()))?;
        self.restore_journal()
    }

    fn apply(
        &self,
        request: &PlatformProxyRequest,
    ) -> Result<PlatformProxyEffect, PlatformProxyError> {
        if !request.endpoint.ip().is_loopback() {
            return Err(PlatformProxyError::NonLoopbackEndpoint);
        }
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| PlatformProxyError::Journal("operation lock poisoned".to_owned()))?;
        self.restore_journal()?;
        let journal = self.capture()?;
        atomic_write_json(&self.journal_path, &journal)?;
        if let Err(error) = self.apply_registry(request) {
            let _ = self.restore_journal();
            return Err(error);
        }
        Ok(PlatformProxyEffect::applied())
    }

    fn restore(&self) -> Result<PlatformProxyEffect, PlatformProxyError> {
        self.recover()
    }
}

#[cfg(windows)]
fn read_registry_value(
    key: &windows_registry::Key,
    name: &str,
) -> Result<Option<SavedRegistryValue>, PlatformProxyError> {
    const FILE_NOT_FOUND_HRESULT: i32 = 0x8007_0002_u32 as i32;
    match key.get_value(name) {
        Ok(value) => Ok(Some(SavedRegistryValue {
            registry_type: value.ty().into(),
            bytes: value.as_ref().to_vec(),
        })),
        Err(error) if error.code().0 == FILE_NOT_FOUND_HRESULT => Ok(None),
        Err(error) => Err(registry_error(error)),
    }
}

#[cfg(windows)]
fn restore_values(
    key: &windows_registry::Key,
    values: Vec<(String, Option<SavedRegistryValue>)>,
) -> Result<(), PlatformProxyError> {
    const FILE_NOT_FOUND_HRESULT: i32 = 0x8007_0002_u32 as i32;
    for (name, value) in values {
        match value {
            Some(value) => key
                .set_bytes(
                    &name,
                    windows_registry::Type::from(value.registry_type),
                    &value.bytes,
                )
                .map_err(registry_error)?,
            None => match key.remove_value(&name) {
                Ok(()) => {}
                Err(error) if error.code().0 == FILE_NOT_FOUND_HRESULT => {}
                Err(error) => return Err(registry_error(error)),
            },
        }
    }
    Ok(())
}

#[cfg(windows)]
fn registry_error(error: impl std::fmt::Display) -> PlatformProxyError {
    PlatformProxyError::Registry(error.to_string())
}

#[cfg(windows)]
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PlatformProxyError> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .ok_or_else(|| PlatformProxyError::Journal("journal has no parent directory".to_owned()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
    let mut file = atomic_write_file::OpenOptions::new()
        .open(path)
        .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
    let encoded = serde_json::to_vec(value)
        .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
    file.write_all(&encoded)
        .map_err(|error| PlatformProxyError::Journal(error.to_string()))?;
    file.commit()
        .map_err(|error| PlatformProxyError::Journal(error.to_string()))
}

#[cfg(windows)]
fn socket_authority(endpoint: SocketAddr) -> String {
    match endpoint {
        SocketAddr::V4(_) => endpoint.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

#[cfg(windows)]
fn refresh_windows_proxy() -> Result<(), PlatformProxyError> {
    const SCRIPT: &str = r#"
Add-Type -Namespace PathChord -Name WinInet -MemberDefinition '
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError=true)]
public static extern bool InternetSetOption(System.IntPtr handle, int option, System.IntPtr buffer, int length);
';
$changed = [PathChord.WinInet]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0);
$refresh = [PathChord.WinInet]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0);
if (-not ($changed -and $refresh)) { exit 1 }
"#;
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .map_err(|error| PlatformProxyError::Refresh(error.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(PlatformProxyError::Refresh(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PlatformProxyRequest {
        PlatformProxyRequest {
            listener_id: ListenerId::new("local-http"),
            kind: PlatformProxyKind::Http,
            endpoint: "127.0.0.1:8080".parse().unwrap(),
        }
    }

    #[test]
    fn fake_adapter_applies_and_restores_exact_request() {
        let adapter = FakePlatformProxyAdapter::new();
        assert_eq!(
            adapter.recover().unwrap(),
            PlatformProxyEffect::not_required()
        );
        assert_eq!(
            adapter.apply(&request()).unwrap(),
            PlatformProxyEffect::applied()
        );
        assert_eq!(adapter.applied(), Some(request()));
        assert_eq!(adapter.restore().unwrap(), PlatformProxyEffect::restored());
        assert_eq!(adapter.applied(), None);
    }

    #[test]
    fn fake_adapter_fails_closed_and_requires_loopback() {
        let adapter = FakePlatformProxyAdapter::new();
        let mut non_loopback = request();
        non_loopback.endpoint = "192.0.2.1:8080".parse().unwrap();
        assert_eq!(
            adapter.apply(&non_loopback),
            Err(PlatformProxyError::NonLoopbackEndpoint)
        );
        adapter.fail_next("registry denied");
        assert_eq!(
            adapter.apply(&request()),
            Err(PlatformProxyError::Injected("registry denied".to_owned()))
        );
        assert_eq!(adapter.applied(), None);
    }

    #[test]
    fn protected_endpoints_replace_as_one_snapshot() {
        let protected = ProtectedEndpointSet::default();
        let first = "192.0.2.1:443".parse().unwrap();
        let second = "[2001:db8::1]:53".parse().unwrap();
        protected.replace([first, second]);
        assert!(protected.contains(&first));
        assert!(protected.contains(&second));
        protected.replace([second]);
        assert!(!protected.contains(&first));
        assert_eq!(protected.snapshot(), BTreeSet::from([second]));
    }
}
