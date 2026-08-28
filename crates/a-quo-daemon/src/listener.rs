use std::fs;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, Protocol, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, listen,
    socket_with,
};
use thiserror::Error;

const APP_RUNTIME_DIRECTORY: &str = "a-quo";
const SOCKET_FILE: &str = "consent.sock";
const LISTEN_BACKLOG: i32 = 8;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("cannot access runtime path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsafe runtime path {path}: {reason}")]
    UnsafeRuntimePath { path: PathBuf, reason: String },

    #[error("refusing to replace an existing consent socket entry: {0}")]
    ExistingSocket(PathBuf),

    #[error("Unix consent socket operation failed: {0}")]
    Socket(#[source] rustix::io::Errno),
}

pub type Result<T> = std::result::Result<T, ListenerError>;

pub struct ConsentListener {
    socket: OwnedFd,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
}

impl ConsentListener {
    pub fn bind(runtime_root: impl AsRef<Path>) -> Result<Self> {
        let runtime_root = runtime_root.as_ref();
        validate_private_directory(runtime_root)?;
        let app_directory = runtime_root.join(APP_RUNTIME_DIRECTORY);
        prepare_app_directory(&app_directory)?;
        let socket_path = app_directory.join(SOCKET_FILE);

        match fs::symlink_metadata(&socket_path) {
            Ok(_) => return Err(ListenerError::ExistingSocket(socket_path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ListenerError::Io {
                    path: socket_path,
                    source,
                });
            }
        }

        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None::<Protocol>,
        )
        .map_err(ListenerError::Socket)?;
        let address = SocketAddrUnix::new(&socket_path).map_err(ListenerError::Socket)?;
        bind(&socket, &address).map_err(ListenerError::Socket)?;

        let metadata = fs::symlink_metadata(&socket_path).map_err(|source| ListenerError::Io {
            path: socket_path.clone(),
            source,
        })?;
        let listener = Self {
            socket,
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
        };
        listener.finish_bind()?;
        Ok(listener)
    }

    pub fn path(&self) -> &Path {
        &self.socket_path
    }

    pub fn accept(&self) -> Result<OwnedFd> {
        let connection =
            accept_with(&self.socket, SocketFlags::CLOEXEC).map_err(ListenerError::Socket)?;
        for timeout in [Timeout::Recv, Timeout::Send] {
            set_socket_timeout(&connection, timeout, Some(CONNECTION_IO_TIMEOUT))
                .map_err(ListenerError::Socket)?;
        }
        Ok(connection)
    }

    fn finish_bind(&self) -> Result<()> {
        fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o600)).map_err(
            |source| ListenerError::Io {
                path: self.socket_path.clone(),
                source,
            },
        )?;
        validate_owned_socket(&self.socket_path, self.socket_device, self.socket_inode)?;
        listen(&self.socket, LISTEN_BACKLOG).map_err(ListenerError::Socket)
    }
}

impl AsFd for ConsentListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl Drop for ConsentListener {
    fn drop(&mut self) {
        if validate_owned_socket(&self.socket_path, self.socket_device, self.socket_inode).is_ok() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn prepare_app_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
                ListenerError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(ListenerError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(unsafe_runtime(path, "the path must be absolute"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| ListenerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_runtime(
            path,
            "the path must be a non-symlink directory",
        ));
    }
    let expected_owner = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_owner {
        return Err(unsafe_runtime(
            path,
            &format!(
                "owner UID {} is not the current effective UID {expected_owner}",
                metadata.uid()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(unsafe_runtime(
            path,
            "group/world permissions are not allowed",
        ));
    }
    Ok(())
}

fn validate_owned_socket(path: &Path, device: u64, inode: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ListenerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_socket()
        || metadata.dev() != device
        || metadata.ino() != inode
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(unsafe_runtime(
            path,
            "the socket entry, owner, inode, or mode changed unexpectedly",
        ));
    }
    Ok(())
}

fn unsafe_runtime(path: &Path, reason: &str) -> ListenerError {
    ListenerError::UnsafeRuntimePath {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_private_socket_and_removes_only_its_own_inode() {
        let runtime = tempfile::tempdir().unwrap();
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let listener = match ConsentListener::bind(runtime.path()) {
            Ok(listener) => listener,
            Err(ListenerError::Socket(rustix::io::Errno::PERM)) => return,
            Err(error) => panic!("listener bind failed unexpectedly: {error}"),
        };
        let socket_path = listener.path().to_path_buf();
        let app_directory = socket_path.parent().unwrap();
        assert_eq!(
            fs::metadata(app_directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(
            ConsentListener::bind(runtime.path()),
            Err(ListenerError::ExistingSocket(_))
        ));
        drop(listener);
        assert!(!socket_path.exists());

        let listener = ConsentListener::bind(runtime.path()).unwrap();
        let socket_path = listener.path().to_path_buf();
        fs::remove_file(&socket_path).unwrap();
        fs::write(&socket_path, b"replacement owned by the test").unwrap();
        drop(listener);
        assert!(socket_path.is_file());
    }

    #[test]
    fn rejects_insecure_runtime_directories() {
        let runtime = tempfile::tempdir().unwrap();
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ConsentListener::bind(runtime.path()),
            Err(ListenerError::UnsafeRuntimePath { .. })
        ));
    }
}
