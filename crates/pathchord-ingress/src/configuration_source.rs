//! Deterministic, bounded loading of one configuration file or a directory bundle.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use tokio::io::AsyncReadExt;

use crate::reload::ReloadError;

pub(crate) const MAX_CONFIGURATION_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_CONFIGURATION_FILES: usize = 1024;
pub(crate) const MAX_CONFIGURATION_DEPTH: usize = 16;

pub async fn load_configuration_documents(
    path: impl Into<PathBuf>,
) -> Result<Vec<String>, ReloadError> {
    let source = ConfigurationSource::bind(path.into()).await?;
    Ok(source.load().await?.documents)
}

#[derive(Debug)]
pub(crate) struct ConfigurationSource {
    path: PathBuf,
    directory: bool,
}

pub(crate) struct ConfigurationDocuments {
    pub(crate) documents: Vec<String>,
    pub(crate) directories: BTreeSet<PathBuf>,
}

impl ConfigurationSource {
    pub(crate) async fn bind(path: PathBuf) -> Result<Self, ReloadError> {
        // The explicitly selected root may be a symlink. Resolve it once;
        // entries discovered inside a directory are never followed.
        let path = tokio::fs::canonicalize(path)
            .await
            .map_err(|_| ReloadError::Io)?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| ReloadError::Io)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(ReloadError::UnsupportedSource);
        }
        Ok(Self {
            path,
            directory: metadata.is_dir(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn base_directory(&self) -> &Path {
        if self.directory {
            &self.path
        } else {
            self.path.parent().expect("a canonical file has a parent")
        }
    }

    pub(crate) fn is_directory(&self) -> bool {
        self.directory
    }

    pub(crate) fn visible_descendant(&self, path: &Path) -> bool {
        path.strip_prefix(&self.path).is_ok_and(|relative| {
            relative.components().all(|component| match component {
                Component::Normal(name) => !ignored_name(name),
                _ => false,
            })
        })
    }

    pub(crate) async fn load(&self) -> Result<ConfigurationDocuments, ReloadError> {
        let metadata = tokio::fs::symlink_metadata(&self.path)
            .await
            .map_err(|_| ReloadError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(ReloadError::Symlink);
        }
        if metadata.is_dir() != self.directory || (!self.directory && !metadata.is_file()) {
            return Err(ReloadError::UnsupportedSource);
        }
        let mut directories = BTreeSet::new();
        let mut files = Vec::new();
        if self.directory {
            let mut pending = vec![(self.path.clone(), 0_usize)];
            while let Some((directory, depth)) = pending.pop() {
                directories.insert(directory.clone());
                let mut entries = tokio::fs::read_dir(&directory)
                    .await
                    .map_err(|_| ReloadError::Io)?;
                while let Some(entry) = entries.next_entry().await.map_err(|_| ReloadError::Io)? {
                    if ignored_name(&entry.file_name()) {
                        continue;
                    }
                    let path = entry.path();
                    let metadata = tokio::fs::symlink_metadata(&path)
                        .await
                        .map_err(|_| ReloadError::Io)?;
                    if metadata.file_type().is_symlink() {
                        return Err(ReloadError::Symlink);
                    }
                    if metadata.is_dir() {
                        if depth >= MAX_CONFIGURATION_DEPTH {
                            return Err(ReloadError::TooDeep);
                        }
                        pending.push((path, depth + 1));
                    } else if is_configuration_file(&path) {
                        if !metadata.is_file() {
                            return Err(ReloadError::UnsupportedSource);
                        }
                        files.push(path);
                        if files.len() > MAX_CONFIGURATION_FILES {
                            return Err(ReloadError::TooManyFiles);
                        }
                    }
                }
            }
            if files.is_empty() {
                return Err(ReloadError::EmptyDirectory);
            }
            files.sort_by(|a, b| {
                a.strip_prefix(&self.path)
                    .unwrap()
                    .cmp(b.strip_prefix(&self.path).unwrap())
            });
        } else {
            files.push(self.path.clone());
        }
        let mut documents = Vec::with_capacity(files.len());
        let mut remaining = MAX_CONFIGURATION_BYTES;
        for path in files {
            let bytes = read_bounded_file(&path, remaining).await?;
            remaining -= bytes.len() as u64;
            documents.push(String::from_utf8(bytes).map_err(|_| ReloadError::Io)?);
        }
        Ok(ConfigurationDocuments {
            documents,
            directories,
        })
    }
}

fn ignored_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with('.') || name.starts_with('#') || name.ends_with('~')
}

pub(crate) fn is_configuration_file(path: &Path) -> bool {
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

async fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ReloadError> {
    let before = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ReloadError::Io)?;
    if before.file_type().is_symlink() {
        return Err(ReloadError::Symlink);
    }
    if !before.is_file() {
        return Err(ReloadError::UnsupportedSource);
    }
    if before.len() > maximum {
        return Err(ReloadError::TooLarge);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ReloadError::Io)?;
    let opened = file.metadata().await.map_err(|_| ReloadError::Io)?;
    let after = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ReloadError::Io)?;
    if after.file_type().is_symlink() {
        return Err(ReloadError::Symlink);
    }
    if !opened.is_file() || !after.is_file() {
        return Err(ReloadError::UnsupportedSource);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
        {
            return Err(ReloadError::Io);
        }
    }
    if opened.len() > maximum {
        return Err(ReloadError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ReloadError::Io)?;
    if bytes.len() as u64 > maximum {
        return Err(ReloadError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
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
            Err(ReloadError::EmptyDirectory)
        ));
        std::fs::write(
            directory.0.join("one.yml"),
            vec![b' '; MAX_CONFIGURATION_BYTES as usize],
        )
        .unwrap();
        std::fs::write(directory.0.join("two.json"), b"{}").unwrap();
        assert!(matches!(source.load().await, Err(ReloadError::TooLarge)));
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
            Err(ReloadError::TooManyFiles)
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
            Err(ReloadError::TooDeep)
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
        assert!(matches!(source.load().await, Err(ReloadError::Symlink)));
    }
}
