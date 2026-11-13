//! Select one configuration source without mixing precedence levels.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("set only one of PATHCHORD_CONFIG and PATHCHORD_CONFIG_DIR")]
    ConflictingEnvironment,
    #[error("a configuration directory was required: {0}")]
    ExpectedDirectory(PathBuf),
    #[error("the current account's home directory could not be determined")]
    MissingHome,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigSelection {
    pub path: PathBuf,
    pub directory: bool,
    pub explicit: bool,
}

impl ConfigSelection {
    pub fn resolve(
        file: Option<&Path>,
        directory: Option<&Path>,
    ) -> Result<Self, ConfigurationError> {
        select(
            file,
            directory,
            std::env::var_os("PATHCHORD_CONFIG"),
            std::env::var_os("PATHCHORD_CONFIG_DIR"),
            default_selection,
        )
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.directory && !self.path.is_dir() {
            return Err(ConfigurationError::ExpectedDirectory(self.path.clone()));
        }
        Ok(())
    }
}

fn select(
    file: Option<&Path>,
    directory: Option<&Path>,
    environment_file: Option<OsString>,
    environment_directory: Option<OsString>,
    default: impl FnOnce() -> Result<ConfigSelection, ConfigurationError>,
) -> Result<ConfigSelection, ConfigurationError> {
    if let Some(path) = directory {
        return Ok(ConfigSelection {
            path: path.to_owned(),
            directory: true,
            explicit: true,
        });
    }
    if let Some(path) = file {
        return Ok(ConfigSelection {
            path: path.to_owned(),
            directory: false,
            explicit: true,
        });
    }
    match (
        environment_file.filter(|value| !value.is_empty()),
        environment_directory.filter(|value| !value.is_empty()),
    ) {
        (Some(_), Some(_)) => Err(ConfigurationError::ConflictingEnvironment),
        (Some(path), None) => Ok(ConfigSelection {
            path: path.into(),
            directory: false,
            explicit: true,
        }),
        (None, Some(path)) => Ok(ConfigSelection {
            path: path.into(),
            directory: true,
            explicit: true,
        }),
        (None, None) => default(),
    }
}

fn account_selection(
    service: bool,
    home: Option<PathBuf>,
) -> Result<ConfigSelection, ConfigurationError> {
    let path = if service {
        PathBuf::from("/etc/pathchord")
    } else {
        home.filter(|home| home.is_absolute())
            .ok_or(ConfigurationError::MissingHome)?
            .join(".config")
            .join("pathchord")
    };
    Ok(ConfigSelection {
        path,
        directory: true,
        explicit: false,
    })
}

#[cfg(unix)]
fn default_selection() -> Result<ConfigSelection, ConfigurationError> {
    use nix::unistd::{Uid, User};
    let uid = Uid::effective();
    if uid.is_root() {
        return account_selection(true, None);
    }
    let account = User::from_uid(uid).ok().flatten();
    let shell = account.as_ref().map(|account| account.shell.as_path());
    let service = service_account(uid.as_raw(), shell);
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| account.map(|account| account.dir));
    account_selection(service, home)
}

#[cfg(unix)]
fn service_account(uid: u32, shell: Option<&Path>) -> bool {
    uid < 1000
        || shell
            .and_then(Path::file_name)
            .is_some_and(|name| name == "nologin" || name == "false")
}

#[cfg(not(unix))]
fn default_selection() -> Result<ConfigSelection, ConfigurationError> {
    let name = std::env::var("USERNAME")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let service = matches!(
        name.as_str(),
        "system" | "local service" | "network service"
    );
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    account_selection(service, home)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default() -> Result<ConfigSelection, ConfigurationError> {
        account_selection(false, Some(std::env::temp_dir()))
    }

    #[test]
    fn command_line_overrides_every_environment_choice() {
        for (file, directory) in [
            (Some(Path::new("explicit.yaml")), None),
            (None, Some(Path::new("explicit.d"))),
        ] {
            let selected = select(
                file,
                directory,
                Some("environment.yaml".into()),
                Some("environment.d".into()),
                || panic!("default must not be evaluated"),
            )
            .unwrap();
            assert_eq!(selected.path, file.or(directory).unwrap());
            assert_eq!(selected.directory, directory.is_some());
        }
    }

    #[test]
    fn environment_overrides_the_default_and_conflicts_are_explicit() {
        let selected = select(None, None, None, Some("from-environment".into()), || {
            panic!("default must not be evaluated")
        })
        .unwrap();
        assert_eq!(selected.path, Path::new("from-environment"));
        assert!(selected.directory);
        assert!(matches!(
            select(None, None, Some("a".into()), Some("b".into()), default),
            Err(ConfigurationError::ConflictingEnvironment)
        ));
        assert_eq!(
            select(None, None, Some(OsString::new()), None, default).unwrap(),
            default().unwrap()
        );
    }

    #[test]
    fn account_defaults_choose_user_home_or_system_directory() {
        let home = std::env::temp_dir().join("account-home");
        assert_eq!(
            account_selection(false, Some(home.clone())).unwrap().path,
            home.join(".config/pathchord")
        );
        assert_eq!(
            account_selection(true, Some(home)).unwrap().path,
            Path::new("/etc/pathchord")
        );
        assert!(matches!(
            account_selection(false, None),
            Err(ConfigurationError::MissingHome)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_service_accounts_use_identity_and_non_login_shells() {
        assert!(service_account(0, Some(Path::new("/bin/sh"))));
        assert!(service_account(999, Some(Path::new("/bin/sh"))));
        assert!(service_account(1001, Some(Path::new("/usr/sbin/nologin"))));
        assert!(service_account(65534, Some(Path::new("/bin/false"))));
        assert!(!service_account(1000, Some(Path::new("/bin/bash"))));
    }
}
