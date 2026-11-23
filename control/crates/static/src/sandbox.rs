//! The content responder's narrowed view.
//!
//! The responder reads one member tree under `root` and the host-to-tree map at
//! `hosts`, and nothing else. Both sockets are bound before this runs, so the
//! view need not carry their directories and the process cannot create, rename
//! or remove a file. On OpenBSD the calls are enforced; elsewhere `restrict` is
//! a no-op so the acceptance suite runs the real binary on a workstation.

use std::path::Path;

use kyriakon_control_core::sandbox;

/// Unveil the two readable trees, lock the list, probe them, then pledge the
/// syscalls a request uses: stdio for the connection and the served file,
/// rpath for the tree, and unix for accept on the already-bound listeners.
pub fn restrict(root: &Path, hosts: &Path) -> Result<(), String> {
    let root = utf8(root, "root")?;
    let hosts = utf8(hosts, "hosts")?;
    sandbox::unveil(root, "r")?;
    sandbox::unveil(hosts, "r")?;
    sandbox::lock()?;
    sandbox::probe(root)?;
    sandbox::probe(hosts)?;
    sandbox::pledge("stdio rpath unix")
}

fn utf8<'a>(path: &'a Path, what: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("the {what} path is not UTF-8: {}", path.display()))
}
