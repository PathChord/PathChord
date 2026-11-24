use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{ConfigurationError, MAX_CONFIGURATION_BYTES};

const LOCK: &str = ".pathchord-lock";
const JOURNAL: &str = ".pathchord-adoption";
const MAX_JOURNAL_BYTES: u64 = MAX_CONFIGURATION_BYTES * 8;

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceChange {
    pub path: PathBuf,
    pub before: Option<String>,
    pub after: String,
}

pub struct SourceTransaction {
    root: PathBuf,
    lock: Option<File>,
    pending: Vec<ResourceChange>,
}

impl SourceTransaction {
    pub async fn begin(root: PathBuf) -> Result<Self, ConfigurationError> {
        Self::open(root, true).await
    }

    pub(crate) async fn read_guard(root: PathBuf) -> Result<Self, ConfigurationError> {
        Self::open(root, false).await
    }

    async fn open(root: PathBuf, writer: bool) -> Result<Self, ConfigurationError> {
        tokio::task::spawn_blocking(move || {
            let path = root.join(LOCK);
            let existing = fs::symlink_metadata(&path);
            if !writer
                && existing
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                return Ok(Self {
                    root,
                    lock: None,
                    pending: Vec::new(),
                });
            }
            if existing.is_ok_and(|metadata| !metadata.is_file()) {
                return Err(ConfigurationError::Symlink);
            }
            let mut options = OpenOptions::new();
            options.read(true).write(writer).create(writer);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o644)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
            }
            let lock = options.open(&path).map_err(|_| ConfigurationError::Io)?;
            #[cfg(unix)]
            if writer {
                use std::os::unix::fs::PermissionsExt;
                let permission = lock
                    .metadata()
                    .map_err(|_| ConfigurationError::Io)?
                    .permissions();
                if permission.mode() & 0o777 != 0o644 {
                    lock.set_permissions(fs::Permissions::from_mode(0o644))
                        .map_err(|_| ConfigurationError::Io)?;
                }
            }
            if writer {
                lock.lock().map_err(|_| ConfigurationError::Io)?;
            } else {
                lock.lock_shared().map_err(|_| ConfigurationError::Io)?;
            }
            let mut transaction = Self {
                root,
                lock: Some(lock),
                pending: Vec::new(),
            };
            if transaction
                .root
                .join(JOURNAL)
                .try_exists()
                .map_err(|_| ConfigurationError::Io)?
            {
                if writer {
                    transaction.recover()?;
                } else {
                    let changes = transaction.read_journal()?;
                    transaction.pending = changes;
                }
            }
            Ok(transaction)
        })
        .await
        .map_err(|_| ConfigurationError::Io)?
    }

    pub(crate) fn lock_appeared(&self) -> bool {
        self.lock.is_none() && self.root.join(LOCK).exists()
    }

    pub fn commit(&self, changes: &[ResourceChange]) -> Result<(), ConfigurationError> {
        self.check(changes)?;
        for change in changes {
            if read_snapshot(&self.root.join(&change.path))? != change.before {
                return Err(ConfigurationError::Transaction(
                    "source changed during editing",
                ));
            }
        }
        if let [change] = changes {
            return write_file(&self.root.join(&change.path), change.after.as_bytes());
        }
        let journal = serde_json::to_vec(changes).map_err(|_| ConfigurationError::Io)?;
        if journal.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ConfigurationError::TooLarge);
        }
        let journal_path = self.root.join(JOURNAL);
        write_journal(&journal_path, &journal, changes)?;
        let result = changes.iter().try_for_each(|change| {
            write_file(&self.root.join(&change.path), change.after.as_bytes())
        });
        if let Err(error) = result {
            self.recover()?;
            return Err(error);
        }
        if let Err(error) = self.clear_journal() {
            self.recover()?;
            return Err(error);
        }
        Ok(())
    }

    fn check(&self, changes: &[ResourceChange]) -> Result<(), ConfigurationError> {
        if self.lock.is_none() || changes.is_empty() || changes.len() > 2 {
            return Err(ConfigurationError::Transaction("invalid transaction"));
        }
        for change in changes {
            if !crate::is_configuration_file(&change.path) {
                return Err(ConfigurationError::UnsupportedSource);
            }
            let mut path = self.root.clone();
            for component in change.path.components() {
                let Component::Normal(name) = component else {
                    return Err(ConfigurationError::UnsupportedSource);
                };
                if crate::ignored_name(name) {
                    return Err(ConfigurationError::UnsupportedSource);
                }
                path.push(name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_symlink() => {
                        return Err(ConfigurationError::Symlink);
                    }
                    Ok(metadata) if path == self.root.join(&change.path) && !metadata.is_file() => {
                        return Err(ConfigurationError::UnsupportedSource);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(ConfigurationError::Io),
                }
            }
        }
        Ok(())
    }

    fn read_journal(&self) -> Result<Vec<ResourceChange>, ConfigurationError> {
        let path = self.root.join(JOURNAL);
        let metadata = fs::symlink_metadata(&path).map_err(|_| ConfigurationError::Io)?;
        if !metadata.is_file() {
            return Err(ConfigurationError::UnsupportedSource);
        }
        let file = File::open(&path).map_err(|_| ConfigurationError::Io)?;
        let mut data = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| ConfigurationError::Io)?;
        if data.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ConfigurationError::TooLarge);
        }
        let changes: Vec<ResourceChange> = serde_json::from_slice(&data)
            .map_err(|_| ConfigurationError::Transaction("invalid recovery record"))?;
        self.check(&changes)?;
        for change in &changes {
            let path = self.root.join(&change.path);
            let current = read_snapshot(&path)?;
            if current != change.before && current.as_deref() != Some(change.after.as_str()) {
                return Err(ConfigurationError::Transaction(
                    "resource was edited during recovery",
                ));
            }
        }
        Ok(changes)
    }

    pub(crate) fn restore_view(
        &self,
        loaded: &mut crate::ConfigurationDocuments,
        source: &crate::ConfigurationSource,
    ) {
        for change in &self.pending {
            let path = self.root.join(&change.path);
            if !source.directory && path != source.path {
                continue;
            }
            if let Some(index) = loaded.files.iter().position(|file| file == &path) {
                if let Some(before) = &change.before {
                    loaded.documents[index].clone_from(before);
                } else {
                    loaded.files.remove(index);
                    loaded.documents.remove(index);
                }
            }
        }
    }

    fn recover(&self) -> Result<(), ConfigurationError> {
        let changes = self.read_journal()?;
        for change in changes {
            let path = self.root.join(change.path);
            if let Some(before) = change.before {
                write_file(&path, before.as_bytes())?;
            } else if path.try_exists().map_err(|_| ConfigurationError::Io)? {
                fs::remove_file(&path).map_err(|_| ConfigurationError::Io)?;
                sync_directory(path.parent().expect("resource has parent"))?;
            }
        }
        self.clear_journal()
    }

    fn clear_journal(&self) -> Result<(), ConfigurationError> {
        fs::remove_file(self.root.join(JOURNAL)).map_err(|_| ConfigurationError::Io)?;
        sync_directory(&self.root)
    }
}

fn read_snapshot(path: &Path) -> Result<Option<String>, ConfigurationError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ConfigurationError::Io),
    };
    let mut contents = String::new();
    file.take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| ConfigurationError::Io)?;
    if contents.len() as u64 > MAX_CONFIGURATION_BYTES {
        return Err(ConfigurationError::TooLarge);
    }
    Ok(Some(contents))
}

fn write_journal(
    path: &Path,
    contents: &[u8],
    changes: &[ResourceChange],
) -> Result<(), ConfigurationError> {
    #[cfg(unix)]
    let group = {
        use std::os::unix::fs::MetadataExt;
        let root = path.parent().expect("journal has a parent");
        let metadata = fs::metadata(root).map_err(|_| ConfigurationError::Io)?;
        let gid = metadata.gid();
        (metadata.mode() & 0o050 == 0o050
            && changes
                .iter()
                .filter(|change| change.before.is_some())
                .all(|change| {
                    fs::metadata(root.join(&change.path)).is_ok_and(|entry| {
                        entry.mode() & 0o004 != 0
                            || (entry.gid() == gid && entry.mode() & 0o040 != 0)
                    })
                }))
        .then_some(gid)
    };
    #[cfg(not(unix))]
    let group = {
        let _ = changes;
        None
    };
    atomic_write(path, contents, group)
}

fn write_file(path: &Path, contents: &[u8]) -> Result<(), ConfigurationError> {
    #[cfg(unix)]
    let group = {
        use std::os::unix::fs::MetadataExt;
        if path.file_name().is_some_and(|name| name == "managed.yaml") && !path.exists() {
            let parent = fs::metadata(path.parent().expect("resource file has parent"))
                .map_err(|_| ConfigurationError::Io)?;
            (parent.mode() & 0o050 == 0o050).then_some(parent.gid())
        } else {
            None
        }
    };
    #[cfg(not(unix))]
    let group = None;
    atomic_write(path, contents, group)
}

fn atomic_write(
    path: &Path,
    contents: &[u8],
    group: Option<u32>,
) -> Result<(), ConfigurationError> {
    #[allow(unused_mut)]
    let mut options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| ConfigurationError::Io)?;
    #[cfg(unix)]
    if let Some(group) = group {
        use std::os::unix::fs::PermissionsExt;
        let gid = nix::unistd::Gid::from_raw(group);
        nix::unistd::fchown(file.as_file(), None, Some(gid)).map_err(|_| ConfigurationError::Io)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o640))
            .map_err(|_| ConfigurationError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = group;
    file.write_all(contents)
        .map_err(|_| ConfigurationError::Io)?;
    file.commit().map_err(|_| ConfigurationError::Io)?;
    sync_directory(path.parent().expect("resource file has parent"))
}

fn sync_directory(path: &Path) -> Result<(), ConfigurationError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ConfigurationError::Io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_stale_resource_contents_before_replacement() {
        let directory = crate::tests::Directory::new();
        let managed = directory.0.join("managed.yaml");
        fs::write(&managed, "changed").unwrap();
        let transaction = SourceTransaction::begin(directory.0.clone()).await.unwrap();
        let result = transaction.commit(&[ResourceChange {
            path: "managed.yaml".into(),
            before: Some("original".into()),
            after: "candidate".into(),
        }]);
        assert!(matches!(result, Err(ConfigurationError::Transaction(_))));
        assert_eq!(fs::read_to_string(managed).unwrap(), "changed");
    }

    #[tokio::test]
    async fn recovers_interrupted_adoption_before_loading() {
        let directory = crate::tests::Directory::new();
        let before = "original\n";
        let managed = directory.0.join("managed.yaml");
        let source = directory.0.join("source.yaml");
        fs::write(&source, before).unwrap();
        let changes = [
            ResourceChange {
                path: "managed.yaml".into(),
                before: None,
                after: before.into(),
            },
            ResourceChange {
                path: "source.yaml".into(),
                before: Some(before.into()),
                after: String::new(),
            },
        ];
        let transaction = SourceTransaction::begin(directory.0.clone()).await.unwrap();
        write_file(
            &directory.0.join(JOURNAL),
            &serde_json::to_vec(&changes).unwrap(),
        )
        .unwrap();
        write_file(&managed, before.as_bytes()).unwrap();
        drop(transaction);
        let source = crate::ConfigurationSource::bind(directory.0.clone())
            .await
            .unwrap();
        let loaded = source.load().await.unwrap();
        assert_eq!(loaded.documents, [before]);
        assert!(managed.exists());
        let transaction = SourceTransaction::begin(directory.0.clone()).await.unwrap();
        assert!(!managed.exists());
        drop(transaction);
        assert!(!directory.0.join(JOURNAL).exists());
    }
}
