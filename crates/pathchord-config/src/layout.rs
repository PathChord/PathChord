use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Ingress,
    Egress,
}

impl Role {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }

    fn socket_name(self) -> String {
        format!("{}.sock", self.name())
    }

    #[cfg(windows)]
    fn pipe(self) -> PathBuf {
        PathBuf::from(format!(r"\\.\pipe\pathchord-{}", self.name()))
    }
}

#[derive(Debug)]
pub struct RoleLayout {
    pub configuration: PathBuf,
    pub state: PathBuf,
    pub socket: PathBuf,
    pub identity: PathBuf,
    pub credentials: PathBuf,
    pub authorization_db: PathBuf,
    pub socket_candidates: Vec<PathBuf>,
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[cfg(unix)]
fn account() -> (bool, Option<PathBuf>) {
    use nix::unistd::{Uid, User};
    let uid = Uid::effective();
    let account = User::from_uid(uid).ok().flatten();
    let service = uid.as_raw() < 1000
        || account.as_ref().is_some_and(|user| {
            user.shell
                .file_name()
                .is_some_and(|name| name == "nologin" || name == "false")
        });
    let home = absolute_env("HOME").or_else(|| {
        account
            .map(|user| user.dir)
            .filter(|path| path.is_absolute())
    });
    (service, home)
}

#[cfg(not(unix))]
fn account() -> (bool, Option<PathBuf>) {
    let username = std::env::var("USERNAME")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let service = matches!(
        username.as_str(),
        "system" | "local service" | "network service"
    );
    (
        service,
        absolute_env("USERPROFILE").or_else(|| absolute_env("HOME")),
    )
}

impl RoleLayout {
    pub fn current(role: Role) -> Result<Self, crate::ConfigurationError> {
        #[cfg(windows)]
        if let Some(root) = absolute_env("ProgramData").map(|path| path.join("PathChord"))
            && root.join("config").join(role.name()).is_dir()
        {
            let name = role.name();
            let state = root.join("data").join(name);
            let socket = role.pipe();
            return Ok(Self {
                configuration: root.join("config").join(name),
                identity: state.join("identity.key"),
                credentials: root.join("credentials").join(name),
                authorization_db: state.join("authorizations.db"),
                state,
                socket_candidates: vec![socket.clone()],
                socket,
            });
        }
        let (service, home) = account();
        Self::resolve(
            role,
            service,
            home.as_deref(),
            absolute_env("XDG_RUNTIME_DIR").as_deref(),
            cfg!(target_os = "freebsd"),
        )
    }

    fn resolve(
        role: Role,
        service: bool,
        home: Option<&Path>,
        runtime: Option<&Path>,
        freebsd: bool,
    ) -> Result<Self, crate::ConfigurationError> {
        let name = role.name();
        let socket_name = role.socket_name();
        let home_config = home.map(|home| home.join(".config/pathchord"));
        let runtime = runtime.map(|runtime| runtime.join("pathchord").join(&socket_name));
        let linux_socket = Path::new("/run/pathchord").join(&socket_name);
        let bsd_socket = Path::new("/var/run/pathchord").join(&socket_name);
        let packaged_socket = if freebsd {
            bsd_socket.clone()
        } else {
            linux_socket.clone()
        };
        let (configuration, state, socket) = if service {
            let state_root = if freebsd {
                "/var/db/pathchord"
            } else {
                "/var/lib/pathchord"
            };
            (
                Path::new("/etc/pathchord").join(name),
                Path::new(state_root).join(name),
                packaged_socket,
            )
        } else {
            let home = home.ok_or(crate::ConfigurationError::MissingHome)?;
            let config = home.join(".config/pathchord");
            let socket = runtime.clone().unwrap_or_else(|| config.join(&socket_name));
            (
                config.join(name),
                home.join(".local/state/pathchord").join(name),
                socket,
            )
        };
        #[cfg(windows)]
        let socket = {
            drop(socket);
            role.pipe()
        };
        let mut socket_candidates = Vec::new();
        if cfg!(windows) {
            socket_candidates.push(socket.clone());
        } else {
            for path in [
                runtime,
                home_config.map(|dir| dir.join(&socket_name)),
                Some(linux_socket),
                Some(bsd_socket),
            ]
            .into_iter()
            .flatten()
            {
                if !socket_candidates.contains(&path) {
                    socket_candidates.push(path);
                }
            }
        }
        Ok(Self {
            configuration,
            socket,
            identity: state.join("identity.key"),
            credentials: state.join("credentials"),
            authorization_db: state.join("authorizations.db"),
            state,
            socket_candidates,
        })
    }

    /// Resolve a configured path relative to the selected resource source.
    pub fn resolve_path(base: &Path, configured: Option<&Path>, default: &Path) -> PathBuf {
        configured.map_or_else(|| default.to_owned(), |path| base.join(path))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn regular_user_paths_and_socket_candidates() {
        let layout = RoleLayout::resolve(
            Role::Ingress,
            false,
            Some(Path::new("/home/operator")),
            Some(Path::new("/run/user/1000")),
            false,
        )
        .unwrap();
        assert_eq!(
            layout.configuration,
            Path::new("/home/operator/.config/pathchord/ingress")
        );
        assert_eq!(
            layout.state,
            Path::new("/home/operator/.local/state/pathchord/ingress")
        );
        assert_eq!(
            layout.socket,
            Path::new("/run/user/1000/pathchord/ingress.sock")
        );
        assert_eq!(
            layout.socket_candidates,
            [
                "/run/user/1000/pathchord/ingress.sock",
                "/home/operator/.config/pathchord/ingress.sock",
                "/run/pathchord/ingress.sock",
                "/var/run/pathchord/ingress.sock",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn packaged_defaults_follow_platform_and_explicit_paths_win() {
        for (freebsd, socket, state) in [
            (
                false,
                "/run/pathchord/egress.sock",
                "/var/lib/pathchord/egress",
            ),
            (
                true,
                "/var/run/pathchord/egress.sock",
                "/var/db/pathchord/egress",
            ),
        ] {
            let layout = RoleLayout::resolve(Role::Egress, true, None, None, freebsd).unwrap();
            assert_eq!(layout.configuration, Path::new("/etc/pathchord/egress"));
            assert_eq!(layout.socket, Path::new(socket));
            assert_eq!(layout.state, Path::new(state));
            assert!(layout.socket_candidates.contains(&layout.socket));
            assert_eq!(
                RoleLayout::resolve_path(
                    Path::new("/config"),
                    Some(Path::new("/private/key")),
                    &layout.identity
                ),
                Path::new("/private/key"),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceOrigin {
    CommandLine,
    Environment,
    AccountDefault,
}

#[derive(Debug)]
pub struct SelectedSource {
    pub path: PathBuf,
    pub directory_required: bool,
    pub origin: SourceOrigin,
}

impl SelectedSource {
    pub fn resolve(
        layout: &RoleLayout,
        file: Option<&Path>,
        directory: Option<&Path>,
    ) -> Result<Self, crate::ConfigurationError> {
        if let Some(path) = directory.or(file) {
            return Ok(Self {
                path: path.to_owned(),
                directory_required: directory.is_some(),
                origin: SourceOrigin::CommandLine,
            });
        }
        let environment_file = std::env::var_os("PATHCHORD_CONFIG").filter(|path| !path.is_empty());
        let environment_directory =
            std::env::var_os("PATHCHORD_CONFIG_DIR").filter(|path| !path.is_empty());
        if environment_file.is_some() && environment_directory.is_some() {
            return Err(crate::ConfigurationError::ConflictingEnvironment);
        }
        let directory_required = environment_directory.is_some();
        if let Some(path) = environment_directory.or(environment_file) {
            return Ok(Self {
                path: path.into(),
                directory_required,
                origin: SourceOrigin::Environment,
            });
        }
        Ok(Self {
            path: layout.configuration.clone(),
            directory_required: true,
            origin: SourceOrigin::AccountDefault,
        })
    }

    pub async fn bind(&self) -> Result<crate::ConfigurationSource, crate::ConfigurationError> {
        let source = crate::ConfigurationSource::bind(self.path.clone()).await?;
        if self.directory_required && !source.is_directory() {
            return Err(crate::ConfigurationError::ExpectedDirectory);
        }
        Ok(source)
    }
}
