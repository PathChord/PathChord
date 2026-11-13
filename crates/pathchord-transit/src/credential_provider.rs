use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    SubscriptionCredentialProvider, TransitCredential, TransitCredentialError,
    TransitCredentialProvider,
};

const MAX_CREDENTIAL_FILE_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_FIELDS: usize = 32;
const MAX_CREDENTIAL_FIELD_NAME_BYTES: usize = 64;
const MAX_CREDENTIAL_VALUE_BYTES: usize = 4096;
const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 128;

#[derive(Clone)]
pub struct FileTransitCredentialProvider {
    root: PathBuf,
}

impl std::fmt::Debug for FileTransitCredentialProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTransitCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl FileTransitCredentialProvider {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TransitCredentialError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(TransitCredentialError::InvalidReference);
        }
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn read_credential(
        &self,
        reference: &str,
    ) -> Result<Option<TransitCredential>, TransitCredentialError> {
        validate_reference(reference)?;
        let path = self.root.join(reference);
        let before = std::fs::symlink_metadata(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => TransitCredentialError::Unavailable,
            _ => TransitCredentialError::Io,
        })?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(TransitCredentialError::UnsafeFileType);
        }
        validate_permissions(&before)?;
        if before.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
            return Err(TransitCredentialError::TooLarge);
        }

        let file = std::fs::File::open(&path).map_err(|_| TransitCredentialError::Io)?;
        let opened = file.metadata().map_err(|_| TransitCredentialError::Io)?;
        validate_same_file(&before, &opened)?;
        validate_permissions(&opened)?;
        let mut body = Zeroizing::new(Vec::with_capacity(before.len() as usize));
        file.take(MAX_CREDENTIAL_FILE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| TransitCredentialError::Io)?;
        if body.len() > MAX_CREDENTIAL_FILE_BYTES {
            return Err(TransitCredentialError::TooLarge);
        }
        let fields: BTreeMap<String, String> =
            serde_json::from_slice(&body).map_err(|_| TransitCredentialError::InvalidDocument)?;
        if fields.is_empty()
            || fields.len() > MAX_CREDENTIAL_FIELDS
            || fields.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > MAX_CREDENTIAL_FIELD_NAME_BYTES
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                    || value.len() > MAX_CREDENTIAL_VALUE_BYTES
            })
        {
            return Err(TransitCredentialError::InvalidDocument);
        }
        Ok(Some(TransitCredential::new(fields)))
    }
}

#[async_trait]
impl TransitCredentialProvider for FileTransitCredentialProvider {
    async fn resolve(
        &self,
        reference: &str,
    ) -> Result<Option<TransitCredential>, TransitCredentialError> {
        let provider = self.clone();
        let reference = reference.to_owned();
        tokio::task::spawn_blocking(move || provider.read_credential(&reference))
            .await
            .map_err(|_| TransitCredentialError::Io)?
    }
}

impl SubscriptionCredentialProvider for FileTransitCredentialProvider {
    fn bearer_token(&self, reference: &str) -> Option<String> {
        self.read_credential(reference)
            .ok()
            .flatten()
            .and_then(|credential| credential.field("bearer_token").map(str::to_owned))
    }
}

fn validate_reference(reference: &str) -> Result<(), TransitCredentialError> {
    if reference.is_empty()
        || reference.len() > MAX_CREDENTIAL_REFERENCE_BYTES
        || reference == "."
        || reference == ".."
        || reference
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        return Err(TransitCredentialError::InvalidReference);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_permissions(metadata: &std::fs::Metadata) -> Result<(), TransitCredentialError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(TransitCredentialError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_permissions(_metadata: &std::fs::Metadata) -> Result<(), TransitCredentialError> {
    Ok(())
}

#[cfg(unix)]
fn validate_same_file(
    before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), TransitCredentialError> {
    use std::os::unix::fs::MetadataExt;

    if before.dev() != opened.dev() || before.ino() != opened.ino() || !opened.is_file() {
        return Err(TransitCredentialError::UnsafeFileType);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(
    _before: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), TransitCredentialError> {
    if !opened.is_file() {
        return Err(TransitCredentialError::UnsafeFileType);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pathchord-transit-credentials-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn reads_bounded_redacted_string_map() {
        let root = directory();
        let path = root.join("proxy-a");
        std::fs::write(
            &path,
            br#"{"username":"user","password":"secret","bearer_token":"token-secret"}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provider = FileTransitCredentialProvider::new(&root).unwrap();
        let credential = provider.resolve("proxy-a").await.unwrap().unwrap();
        assert_eq!(credential.field("username"), Some("user"));
        assert!(!format!("{credential:?}").contains("secret"));
        drop(credential);
        assert_eq!(
            provider.bearer_token("proxy-a").as_deref(),
            Some("token-secret")
        );
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn rejects_traversal_and_symlinks() {
        let root = directory();
        let provider = FileTransitCredentialProvider::new(&root).unwrap();
        assert_eq!(
            provider.resolve("../outside").await,
            Err(TransitCredentialError::InvalidReference)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.join("target");
            let link = root.join("link");
            std::fs::write(&target, b"{}").unwrap();
            symlink(&target, &link).unwrap();
            assert_eq!(
                provider.resolve("link").await,
                Err(TransitCredentialError::UnsafeFileType)
            );
            std::fs::remove_file(link).unwrap();
            std::fs::remove_file(target).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_group_or_world_readable_files() {
        use std::os::unix::fs::PermissionsExt;

        let root = directory();
        let path = root.join("wide");
        std::fs::write(&path, br#"{"password":"secret"}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let provider = FileTransitCredentialProvider::new(&root).unwrap();
        assert_eq!(
            provider.resolve("wide").await,
            Err(TransitCredentialError::InsecurePermissions)
        );
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
