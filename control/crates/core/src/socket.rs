//! The Unix listener both responders bind: the socket, its mode, the accept
//! loop, the per-listener permit count, and the descriptor budget the login
//! class gives the process.
//!
//! The FastCGI server and the portal's line protocol differ above this module.
//! What they share is here: a mode-0660 socket that clears whatever a previous
//! run left at the path, a bound on connections served at once, and an accept
//! error that is reported and waited out rather than returned, because returning
//! it would cancel the process's other listeners.

use std::future::Future;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// The descriptors the daemons may hold: the `daemon` login class gives them
/// `openfiles-cur=128`, and each listener's permit count is a slice of it.
pub const OPEN_FILES: usize = 128;

/// What the process keeps outside its listeners: the store's files, the config,
/// the log and the standard streams. The listener budgets must fit in what is
/// left.
pub const RESERVED_FILES: usize = 32;

/// How long the accept loop waits after an error it cannot attribute to a dead
/// connection. A full descriptor table (`EMFILE`, `ENFILE`) leaves the backlog
/// as ready as it was, so an unpaused retry would spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What one listener may serve.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections served at once on this listener. Each one holds a descriptor,
    /// so the listeners' counts must fit in the login class's file table.
    pub connections: usize,
    /// The longest one operation on a connection may take. The FastCGI server
    /// applies it per read and per record written; a caller with a different
    /// shape applies it around its own work.
    pub deadline: Duration,
    /// The syslog program name this listener's lines carry, so an operator's
    /// grep for the responder that logged them finds them.
    pub program: &'static str,
}

/// Bind `path`, replacing whatever a previous run left there, with mode 0660 so
/// the socket directory's group decides who may connect. A socket file outlives
/// the process that made it, so a restart after a crash would otherwise fail to
/// bind until somebody removed it by hand. `symlink_metadata` makes a dangling
/// symlink a file to clear rather than the `ENOENT` a following `metadata`
/// reports, and `remove_file` unlinks the symlink itself, never its target.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path)?,
        Err(source) if source.kind() == ErrorKind::NotFound => {}
        Err(source) => return Err(source),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// How long the accept loop waits after an error it cannot attribute to a dead
/// connection. `accept(2)`'s errors are the connection's, not the listener's: a
/// connection that died in the queue (`ECONNABORTED`) or a signal (`EINTR`) has
/// already left the backlog, so the next call runs at once, and everything else
/// is treated as the descriptor limit.
fn backoff(error: &std::io::Error) -> Duration {
    match error.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted => Duration::ZERO,
        _ => ACCEPT_BACKOFF,
    }
}

/// Serve a Unix listener at `limits.connections` at a time until the listener
/// cannot accept. `what` is the listener's word in the log lines.
///
/// The permit is taken before the task is spawned, so a flood costs the
/// listening backlog and one accepted socket rather than a task and a descriptor
/// per waiting connection. An accept error is a connection a flood provoked, not
/// the listener: returning it would cancel the process's other listeners, so the
/// loop reports, waits and continues. The connection future's own deadline is
/// the closure's to apply, because a streaming reply resets it per record.
pub async fn accept<F, Fut>(
    listener: UnixListener,
    limits: Limits,
    what: &'static str,
    served: F,
) -> std::io::Result<()>
where
    F: Fn(UnixStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(limits.connections));
    let served = Arc::new(served);
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                crate::util::log(&format!(
                    "{}: cannot accept a {what} connection: {error}",
                    limits.program
                ));
                tokio::time::sleep(backoff(&error)).await;
                continue;
            }
        };
        let permit = match slots.clone().acquire_owned().await {
            Ok(permit) => permit,
            // The semaphore is never closed while the process lives.
            Err(_) => return Ok(()),
        };
        let served = served.clone();
        tokio::spawn(async move {
            // Held for as long as this connection is served.
            let _permit = permit;
            served(stream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory with a socket path of its own, so each test's listener cannot
    /// collide with another's.
    fn temp_socket(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "kyriakon-socket-{}-{name}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.sock");
        (dir, path)
    }

    /// A file or a dangling symlink left at the path is cleared, and the link's
    /// target is untouched.
    #[tokio::test]
    async fn bind_clears_a_file_or_a_dangling_link_at_the_path() {
        use std::os::unix::fs::{symlink, FileTypeExt};

        let (dir, path) = temp_socket("bind");
        std::fs::write(&path, b"planted").unwrap();
        let listener = bind(&path).expect("bind over a planted file");
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);

        let target = dir.join("gone");
        std::fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        let listener = bind(&path).expect("bind over a dangling symlink");
        assert!(
            target.symlink_metadata().is_err(),
            "the link's target is untouched"
        );
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);
    }

    /// An accept error is the listener's only when the backlog may still be
    /// full: a connection that aborted or a signal has already left the queue,
    /// so retrying at once is right for those.
    #[test]
    fn an_accept_error_is_waited_out_only_when_the_listener_is_the_problem() {
        assert_eq!(
            backoff(&std::io::Error::from(ErrorKind::ConnectionAborted)),
            Duration::ZERO
        );
        assert_eq!(
            backoff(&std::io::Error::from(ErrorKind::Interrupted)),
            Duration::ZERO
        );
        assert_eq!(
            backoff(&std::io::Error::from(ErrorKind::Other)),
            ACCEPT_BACKOFF
        );
    }
}
