//! Resolving a request to a file inside one member's root, and nowhere else.
//!
//! The daemons open a composed path and check `S_ISREG` afterwards, which is why
//! a link they follow can leave the tree they mean to serve. Here every step is
//! relative to the descriptor of the directory above it and carries `O_NOFOLLOW`,
//! so a link fails the open itself: there is no window between a check and a use
//! for a member to win, and the file that comes back was reached without a single
//! link being followed.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::mime::media_type;

/// A file that may be served, and the type it is announced as.
pub struct Served {
    pub file: File,
    pub media: &'static str,
}

/// Why a request is refused.
///
/// Both are a 404 to the client. The difference is only what the server's own log
/// can say, because a client that could tell "no such file" from "not a file"
/// would learn which of its guesses resolved.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A component names nothing in this tree, or the tree itself is gone.
    Missing,
    /// The name resolved to something that is not a served file.
    NotAFile,
}

/// Open the file `request` names under `root`, or refuse it.
///
/// `request` is the path the front end passed, with the query already gone and
/// still percent-encoded. It is deliberately not decoded here: both daemons
/// decode the path they send, so decoding again would turn `%252e%252e` into a
/// traversal that neither of them intended to allow.
pub fn open(root: &Path, request: &str) -> Result<Served, Refusal> {
    let names = components(request)?;
    let mut current = File::open(root).map_err(|_| Refusal::Missing)?;
    if names.is_empty() {
        return index_in(&current);
    }
    for (position, name) in names.iter().enumerate() {
        let next = step(&current, name).ok_or(Refusal::Missing)?;
        if position + 1 < names.len() {
            current = next;
            continue;
        }
        let metadata = next.metadata().map_err(|_| Refusal::Missing)?;
        if metadata.is_dir() {
            return index_in(&next);
        }
        if !metadata.is_file() {
            return Err(Refusal::NotAFile);
        }
        return Ok(Served {
            media: media_type(name),
            file: next,
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

/// `index.html` in a directory, which is the only file a directory request ever
/// serves: a listing would publish names the member did not link.
fn index_in(directory: &File) -> Result<Served, Refusal> {
    let file = step(directory, "index.html").ok_or(Refusal::Missing)?;
    let metadata = file.metadata().map_err(|_| Refusal::Missing)?;
    if !metadata.is_file() {
        return Err(Refusal::NotAFile);
    }
    Ok(Served {
        file,
        media: media_type("index.html"),
    })
}

/// One path component, relative to an open directory and refusing a link.
fn step(directory: &File, name: &str) -> Option<File> {
    let name = CString::new(name).ok()?;
    // SAFETY: `directory` is an open descriptor, `name` is a NUL-terminated string
    // that outlives the call, and the returned descriptor is taken ownership of by
    // the `File` built from it. `O_NOFOLLOW` is the entire point of the call: a
    // symlink makes `openat` fail instead of being followed.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: the descriptor is fresh and owned here, and nothing else holds it.
    Some(unsafe { File::from_raw_fd(fd) })
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
            let base = std::env::temp_dir().join(format!(
                "kyriakon-static-{}-{:x}",
                std::process::id(),
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
                root.join(".git"),
                outside.parent().unwrap().to_path_buf(),
            ] {
                std::fs::create_dir_all(dir).expect("fixture directory");
            }
            std::fs::write(root.join("index.html"), b"alice site").expect("index");
            std::fs::write(root.join("sub/index.html"), b"sub site").expect("sub index");
            std::fs::write(root.join("sub/page.css"), b"body{}").expect("css");
            std::fs::write(root.join(".git/config"), b"[core]").expect("git config");
            std::fs::write(&outside, b"bob wrote this").expect("outside");
            symlink("../../bob.kyriakon.net/www/secret.html", root.join("leak"))
                .expect("relative link");
            symlink(
                "/home/www/bob.kyriakon.net/www/secret.html",
                root.join("gitleak"),
            )
            .expect("absolute link");
            symlink("index.html", root.join("selflink")).expect("in-tree link");
            symlink("sub", root.join("sublink")).expect("directory link");
            Tree { root, outside }
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.root.parent().and_then(|p| p.parent()).unwrap());
        }
    }

    fn body(root: &Path, request: &str) -> Result<String, Refusal> {
        let mut served = open(root, request)?;
        let mut text = String::new();
        served
            .file
            .read_to_string(&mut text)
            .expect("the fixture is text");
        Ok(text)
    }

    #[test]
    fn a_plain_file_is_served_with_its_type() {
        let tree = Tree::new();
        assert_eq!(body(&tree.root, "/sub/page.css"), Ok("body{}".to_string()));
        assert_eq!(media_type("page.css"), "text/css; charset=utf-8");
    }

    #[test]
    fn a_directory_serves_its_index() {
        let tree = Tree::new();
        assert_eq!(body(&tree.root, "/"), Ok("alice site".to_string()));
        assert_eq!(body(&tree.root, "/sub/"), Ok("sub site".to_string()));
        // With no index there is nothing to serve, and no listing is invented.
        assert_eq!(body(&tree.root, "/empty/"), Err(Refusal::Missing));
    }

    #[test]
    fn a_link_is_never_followed() {
        let tree = Tree::new();
        // Out of the tree, by a relative target and by an absolute one.
        assert_eq!(body(&tree.root, "/leak"), Err(Refusal::Missing));
        assert_eq!(body(&tree.root, "/gitleak"), Err(Refusal::Missing));
        // And even a link that points inside it: the daemons cannot tell, and one
        // rule is cheaper to keep right than two.
        assert_eq!(body(&tree.root, "/selflink"), Err(Refusal::Missing));
        // A linked directory is refused at the component that is a link.
        assert_eq!(body(&tree.root, "/sublink/page.css"), Err(Refusal::Missing));
        // The file outside really is there, so the refusals above are the walk,
        // not a broken fixture.
        assert_eq!(
            std::fs::read_to_string(&tree.outside).expect("the outside file"),
            "bob wrote this"
        );
    }

    #[test]
    fn a_dot_component_is_never_served() {
        let tree = Tree::new();
        assert_eq!(body(&tree.root, "/.git/config"), Err(Refusal::Missing));
        // Percent-encoded, because neither daemon decodes here and a file literally
        // named `%2e%2e` is not one of the member's.
        assert_eq!(
            body(&tree.root, "/%2e%2e/bob.kyriakon.net/www/secret.html"),
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
            "//index.html",
            "/sub//index.html",
            "/nul\0byte",
        ] {
            assert_eq!(
                body(&tree.root, request),
                Err(Refusal::Missing),
                "{request}"
            );
        }
    }

    #[test]
    fn a_missing_file_is_missing() {
        let tree = Tree::new();
        assert_eq!(body(&tree.root, "/nothing.html"), Err(Refusal::Missing));
        assert_eq!(body(&tree.root, "/sub"), Ok("sub site".to_string()));
    }
}
