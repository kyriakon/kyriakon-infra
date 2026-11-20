#![no_main]

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;

use kyriakon_control_static::{open, Served};

/// The tree every input is resolved against, built once. It holds a real file
/// outside it that a link aims at, so a walk that escaped would hand back an
/// inode the allowed set does not name.
struct Tree {
    root: PathBuf,
    allowed: BTreeSet<u64>,
}

static TREE: LazyLock<Tree> = LazyLock::new(|| {
    let base = std::env::temp_dir().join(format!("kyriakon-fuzz-static-{}", std::process::id()));
    let root = base.join("alice.kyriakon.net/www");
    let outside = base.join("bob.kyriakon.net/www/secret.html");
    for dir in [root.join("sub"), outside.parent().unwrap().to_path_buf()] {
        std::fs::create_dir_all(dir).expect("fixture directory");
    }
    let files = [
        (root.join("index.html"), b"alice".to_vec()),
        (root.join("sub/index.html"), b"sub".to_vec()),
        (root.join("sub/page.css"), b"body{}".to_vec()),
        (outside.clone(), b"bob".to_vec()),
    ];
    let mut allowed = BTreeSet::new();
    for (path, body) in &files {
        std::fs::write(path, body).expect("fixture file");
    }
    // Only the files inside the root are legal answers: the outside file is in the
    // tree so a link to it is a real link, and its inode must never come back.
    for (path, _) in &files {
        if path.starts_with(&root) {
            let inode = std::fs::metadata(path).expect("fixture metadata").ino();
            allowed.insert(inode);
        }
    }
    std::os::unix::fs::symlink(&outside, root.join("leak")).expect("outside link");
    std::os::unix::fs::symlink("sub/page.css", root.join("selflink")).expect("inside link");
    Tree { root, allowed }
});

/// Every request the front ends can pass, including the ones no browser sends.
///
/// The assertions are the resolver's contract, not a round trip: a served file is
/// always one of the fixture's own, whatever the request was. A hang is a finding
/// too, and the workflow's `-timeout` turns one into an artifact.
fuzz_target!(|data: &[u8]| {
    let tree = &*TREE;
    let request = String::from_utf8_lossy(data);
    if let Ok(Served::File { file, .. }) = open(&tree.root, &request, "index.html") {
        let inode = file.metadata().expect("served file metadata").ino();
        assert!(
            tree.allowed.contains(&inode),
            "served a file outside the member's root for {request:?}"
        );
    }
});
