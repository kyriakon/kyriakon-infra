//! Resolving a request to a file inside one member's root, and nowhere else.
//!
//! The daemons open a composed path and check `S_ISREG` afterwards, which is why
//! a link they follow can leave the tree they mean to serve. Here every step is
//! relative to the descriptor of the directory above it and carries `O_NOFOLLOW`,
//! so a link fails the open itself: there is no window between a check and a use
//! for a member to win, and the file that comes back was reached without a single
//! link being followed.
//!
//! `O_NONBLOCK` goes with it. A FIFO in a served tree cannot be created over
//! sftp today, but a read-only open of one blocks until a writer arrives, and a
//! request that hangs instead of being refused costs a worker for as long as the
//! member leaves it there. With the flag the open returns at once and the
//! non-regular check refuses it.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::mime::media_type;

/// What a request resolved to.
pub enum Served {
    /// The file to send, the type to announce it as, and when it last changed.
    /// The time is what lets a browser ask whether its copy is still current;
    /// it is `None` only when the filesystem cannot say.
    File {
        file: File,
        media: &'static str,
        modified: Option<std::time::SystemTime>,
        /// The length the descriptor reported. A `HEAD` answers with it and the
        /// over-cap check uses it, without either reading the bytes.
        len: u64,
    },
    /// The request named a directory without its trailing separator. The caller
    /// answers with a redirect to the same path with one: a browser resolves a
    /// relative link against the URL, so serving `sub/index.html` at `/sub` sends
    /// every request for a sibling of that page to the wrong place.
    Redirect,
}

/// Why a request is refused.
///
/// `Missing` and `NotAFile` are both a 404 to the client. The difference is only
/// what the server's own log can say, because a client that could tell "no such
/// file" from "not a file" would learn which of its guesses resolved. `Exhausted`
/// is the process's own failure, so it is a 503 and a log line rather than a
/// 404 that hides a full descriptor table ([#877]).
///
/// [#877]: https://github.com/kyriakon/kyriakon-infra/issues/877
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A component names nothing in this tree, or the tree itself is gone.
    Missing,
    /// The name resolved to something that is not a served file.
    NotAFile,
    /// `open` failed because the process has no descriptor left (`EMFILE` or
    /// `ENFILE`). The answer is temporary, and the failure is the server's.
    Exhausted,
}

/// Whether an `open`/`openat` failure is a missing name or the process running out
/// of descriptors. Rust has no stable `ErrorKind` for `EMFILE` and `ENFILE`, so
/// the raw errno is the test.
fn refusal(error: &std::io::Error) -> Refusal {
    match error.raw_os_error() {
        Some(libc::EMFILE) | Some(libc::ENFILE) => Refusal::Exhausted,
        _ => Refusal::Missing,
    }
}

/// Open the file `request` names under `root`, or refuse it.
///
/// `request` is the decoded path with its query already cut, and the caller is
/// what makes it so: gmid's `GEMINI_URL_PATH` arrives that way, and httpd's
/// `REQUEST_URI` is decoded by the responder the same way it decodes its own
/// routes. Decoding here instead would turn `%252e%252e` into a traversal
/// neither front end meant to allow.
///
/// `index` is the file a directory serves, and it differs by protocol: the web
/// tree's is `index.html`, a capsule's is `index.gmi`.
pub fn open(root: &Path, request: &str, index: &str) -> Result<Served, Refusal> {
    let names = components(request)?;
    let mut current = open_root(root)?;
    if names.is_empty() {
        return index_in(&current, index);
    }
    for (position, name) in names.iter().enumerate() {
        let next = step(&current, name)?;
        if position + 1 < names.len() {
            current = next;
            continue;
        }
        let metadata = next.metadata().map_err(|_| Refusal::Missing)?;
        if metadata.is_dir() {
            if !request.ends_with('/') {
                return Ok(Served::Redirect);
            }
            return index_in(&next, index);
        }
        if !metadata.is_file() {
            return Err(Refusal::NotAFile);
        }
        // `a.html/` and `a.html` are two spellings of one file, and only one of
        // them should resolve. A browser at the first resolves a relative link
        // against a directory that does not exist.
        if request.ends_with('/') {
            return Err(Refusal::Missing);
        }
        return Ok(Served::File {
            file: next,
            media: media_type(name),
            modified: metadata.modified().ok(),
            len: metadata.len(),
        });
    }
    // `names` is non-empty here and the loop returns on its last component.
    Err(Refusal::Missing)
}

/// The request split into names, or a refusal.
///
/// `..` and `.` cannot appear, so no request can walk upwards; a name beginning
/// with a dot cannot appear, so no request can read `.git` or any other file the
/// uploader was not meant to publish; and an empty component is refused rather
/// than skipped, because `a//b` and `a/b` are two spellings of one path and only
/// one of them should resolve. Exactly one leading and one trailing separator are
/// stripped for the same reason: a second one is an empty component, not spelling.
fn components(request: &str) -> Result<Vec<&str>, Refusal> {
    if request.starts_with("//") || request.ends_with("//") {
        return Err(Refusal::Missing);
    }
    let trimmed = request.strip_prefix('/').unwrap_or(request);
    let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for name in trimmed.split('/') {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.starts_with('.')
            || name.contains('\0')
        {
            return Err(Refusal::Missing);
        }
        names.push(name);
    }
    Ok(names)
}

/// The index file in a directory, which is the only file a directory request ever
/// serves: a listing would publish names the member did not link.
fn index_in(directory: &File, index: &str) -> Result<Served, Refusal> {
    let file = step(directory, index)?;
    let metadata = file.metadata().map_err(|_| Refusal::Missing)?;
    if !metadata.is_file() {
        return Err(Refusal::NotAFile);
    }
    Ok(Served::File {
        file,
        media: media_type(index),
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

/// The tree root, as a directory descriptor that was opened without following a
/// link and cannot block.
///
/// Every step below this already refuses a link, but the root itself is a
/// composed path: `File::open` would follow a link at any component of
/// `<root>/<host>/<www|gemini>`, and it would block on a FIFO placed at the last
/// one until a writer arrived. `O_DIRECTORY` refuses a FIFO and a regular file
/// at once; `O_NOFOLLOW` refuses the link. Ownership already keeps a member out
/// of the directory that holds these names, and this is the second lock on the
/// same door.
fn open_root(root: &Path) -> Result<File, Refusal> {
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Refusal::Missing)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call, and the
    // returned descriptor is taken ownership of by the `File` built from it.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(refusal(&std::io::Error::last_os_error()));
    }
    // SAFETY: the descriptor is fresh and owned here, and nothing else holds it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// One path component, relative to an open directory and refusing a link.
fn step(directory: &File, name: &str) -> Result<File, Refusal> {
    let name = CString::new(name).map_err(|_| Refusal::Missing)?;
    // SAFETY: `directory` is an open descriptor, `name` is a NUL-terminated string
    // that outlives the call, and the returned descriptor is taken ownership of by
    // the `File` built from it. `O_NOFOLLOW` is the entire point of the call: a
    // symlink makes `openat` fail instead of being followed. `O_NONBLOCK` is what
    // keeps a FIFO from blocking the open before it can be refused.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(refusal(&std::io::Error::last_os_error()));
    }
    // SAFETY: the descriptor is fresh and owned here, and nothing else holds it.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    /// A tree with the cases a member site can present, and a file outside it that
    /// the links aim at.
    struct Tree {
        root: std::path::PathBuf,
        outside: std::path::PathBuf,
    }

    impl Tree {
        fn new() -> Tree {
            // The clock alone is not unique: macOS reports microseconds, and the
            // tests run in parallel, so two trees can be built in one tick.
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "kyriakon-static-{}-{:x}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let root = base.join("alice.kyriakon.net/www");
            let outside = base.join("bob.kyriakon.net/www/secret.html");
            for dir in [
                root.join("sub"),
                root.join("empty"),
                root.join("badindex/index.html"),
                root.join(".git"),
                outside.parent().unwrap().to_path_buf(),
            ] {
                std::fs::create_dir_all(dir).expect("fixture directory");
            }
            std::fs::write(root.join("index.html"), b"alice site").expect("index");
            std::fs::write(root.join("sub/index.html"), b"sub site").expect("sub index");
            std::fs::write(root.join("sub/page.css"), b"body{}").expect("css");
            std::fs::write(root.join("my page.html"), b"spaced").expect("spaced name");
            std::fs::write(root.join(".git/config"), b"[core]").expect("git config");
            std::fs::write(&outside, b"bob wrote this").expect("outside");
            // The absolute target is the real file, so the refusal cannot pass for
            // a missing one: an absent target makes `openat` answer ENOENT with or
            // without `O_NOFOLLOW`.
            symlink(&outside, root.join("gitleak")).expect("absolute link");
            symlink("../../bob.kyriakon.net/www/secret.html", root.join("leak"))
                .expect("relative link");
            symlink("index.html", root.join("selflink")).expect("in-tree link");
            symlink("sub", root.join("sublink")).expect("directory link");
            // A FIFO, which a plain read-only open would block on.
            let pipe = CString::new(root.join("pipe").to_str().unwrap()).expect("path");
            // SAFETY: `pipe` is a NUL-terminated path under the fixture, and the
            // call only creates it.
            unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) };
            Tree { root, outside }
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let base = self.root.parent().and_then(|p| p.parent()).expect("base");
            let _ = std::fs::remove_dir_all(base);
        }
    }

    /// The body of a served file, or what the resolver refused with.
    fn body(root: &Path, request: &str, index: &str) -> Result<String, Refusal> {
        match open(root, request, index)? {
            Served::File { mut file, .. } => {
                let mut text = String::new();
                file.read_to_string(&mut text).expect("the fixture is text");
                Ok(text)
            }
            Served::Redirect => Ok("<redirect>".to_string()),
        }
    }

    fn media(root: &Path, request: &str) -> &'static str {
        match open(root, request, "index.html").expect("served") {
            Served::File { media, .. } => media,
            Served::Redirect => panic!("expected a file"),
        }
    }

    #[test]
    fn a_plain_file_is_served_with_its_type() {
        let tree = Tree::new();
        assert_eq!(
            body(&tree.root, "/sub/page.css", "index.html"),
            Ok("body{}".to_string())
        );
        assert_eq!(
            media(&tree.root, "/sub/page.css"),
            "text/css; charset=utf-8"
        );
        // The caller hands over the decoded path, so a name with a space arrives
        // as the name on disk.
        assert_eq!(
            body(&tree.root, "/my page.html", "index.html"),
            Ok("spaced".to_string())
        );
    }

    #[test]
    fn a_directory_serves_its_index() {
        let tree = Tree::new();
        assert_eq!(
            body(&tree.root, "/", "index.html"),
            Ok("alice site".to_string())
        );
        assert_eq!(
            body(&tree.root, "/sub/", "index.html"),
            Ok("sub site".to_string())
        );
        // With no index there is nothing to serve, and no listing is invented.
        assert_eq!(
            body(&tree.root, "/empty/", "index.html"),
            Err(Refusal::Missing)
        );
    }

    #[test]
    fn a_capsule_serves_its_own_index_name() {
        let tree = Tree::new();
        std::fs::write(tree.root.join("gemini.gmi"), b"20 text/gemini\r\nhi").expect("gemtext");
        std::fs::rename(
            tree.root.join("gemini.gmi"),
            tree.root.join("sub/index.gmi"),
        )
        .expect("rename into sub");
        assert_eq!(
            body(&tree.root, "/sub/", "index.gmi"),
            Ok("20 text/gemini\r\nhi".to_string())
        );
        assert_eq!(
            media(&tree.root, "/sub/index.gmi"),
            "text/gemini; charset=utf-8"
        );
    }

    #[test]
    fn a_directory_without_its_separator_is_a_redirect() {
        let tree = Tree::new();
        assert_eq!(
            body(&tree.root, "/sub", "index.html"),
            Ok("<redirect>".to_string())
        );
    }

    #[test]
    fn a_link_is_never_followed() {
        let tree = Tree::new();
        // Out of the tree, by a relative target and by an absolute one, and the
        // absolute one names a file that exists, so ENOENT cannot be mistaken for
        // the refusal.
        assert_eq!(
            body(&tree.root, "/leak", "index.html"),
            Err(Refusal::Missing)
        );
        assert_eq!(
            body(&tree.root, "/gitleak", "index.html"),
            Err(Refusal::Missing)
        );
        // And even a link that points inside it: the daemons cannot tell, and one
        // rule is cheaper to keep right than two.
        assert_eq!(
            body(&tree.root, "/selflink", "index.html"),
            Err(Refusal::Missing)
        );
        // A linked directory is refused at the component that is a link.
        assert_eq!(
            body(&tree.root, "/sublink/page.css", "index.html"),
            Err(Refusal::Missing)
        );
        // The file outside really is there, so the refusals above are the walk,
        // not a broken fixture.
        assert_eq!(
            std::fs::read_to_string(&tree.outside).expect("the outside file"),
            "bob wrote this"
        );
    }

    #[test]
    fn a_non_file_is_refused_rather_than_hanging_or_served() {
        let tree = Tree::new();
        // A FIFO opened read-only without `O_NONBLOCK` blocks; here it is refused.
        assert_eq!(
            body(&tree.root, "/pipe", "index.html"),
            Err(Refusal::NotAFile)
        );
        // A directory standing where the index should be is refused for the same
        // reason: neither is a file to send.
        assert_eq!(
            body(&tree.root, "/badindex/", "index.html"),
            Err(Refusal::NotAFile)
        );
    }

    #[test]
    fn a_dot_component_is_never_served() {
        let tree = Tree::new();
        assert_eq!(
            body(&tree.root, "/.git/config", "index.html"),
            Err(Refusal::Missing)
        );
        // Percent-encoded, because the resolver is handed the decoded path and a
        // file literally named `%2e%2e` is not one of the member's.
        assert_eq!(
            body(
                &tree.root,
                "/%2e%2e/bob.kyriakon.net/www/secret.html",
                "index.html"
            ),
            Err(Refusal::Missing)
        );
    }

    #[test]
    fn no_request_climbs_or_doubles_a_separator() {
        let tree = Tree::new();
        for request in [
            "/../bob.kyriakon.net/www/secret.html",
            "/sub/../../bob.kyriakon.net/www/secret.html",
            "/./index.html",
            "//",
            "//index.html",
            "/sub//index.html",
            "/nul\0byte",
        ] {
            assert_eq!(
                body(&tree.root, request, "index.html"),
                Err(Refusal::Missing),
                "{request}"
            );
        }
    }

    #[test]
    fn a_missing_file_is_missing() {
        let tree = Tree::new();
        assert_eq!(
            body(&tree.root, "/nothing.html", "index.html"),
            Err(Refusal::Missing)
        );
        assert_eq!(
            body(&tree.root, "/sub/", "index.html"),
            Ok("sub site".to_string())
        );
    }

    /// `EMFILE` and `ENFILE` are the process's failure, not the member's missing
    /// file, and Rust has no stable `ErrorKind` for either ([#877]).
    ///
    /// [#877]: https://github.com/kyriakon/kyriakon-infra/issues/877
    #[test]
    fn a_full_descriptor_table_is_not_a_missing_file() {
        for code in [libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                refusal(&std::io::Error::from_raw_os_error(code)),
                Refusal::Exhausted,
                "errno {code}"
            );
        }
        assert_eq!(
            refusal(&std::io::Error::from_raw_os_error(libc::ENOENT)),
            Refusal::Missing
        );
        assert_eq!(
            refusal(&std::io::Error::from_raw_os_error(libc::ELOOP)),
            Refusal::Missing,
            "a link is a refusal to serve, not a server failure"
        );
    }
}
