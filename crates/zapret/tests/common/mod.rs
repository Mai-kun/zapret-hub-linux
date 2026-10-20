#![allow(dead_code)]

use std::fs;

/// A minimal Flowseal folder: what `Folder::open` checks, plus `utils\`.
pub fn fake_zapret() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("service.bat"),
        "@echo off\r\nset \"LOCAL_VERSION=1.10.3\"\r\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(root.join("bin").join("winws.exe"), b"").unwrap();
    fs::write(root.join("bin").join("WinDivert64.sys"), b"").unwrap();
    fs::create_dir_all(root.join("lists")).unwrap();
    fs::create_dir_all(root.join("utils")).unwrap();
    dir
}

pub fn folder(dir: &tempfile::TempDir) -> zapret::folder::Folder {
    zapret::folder::Folder::open(dir.path()).unwrap()
}

/// Keeps `path` the way a virus scanner or an editor with no sharing might: nothing else may
/// open it for reading until the lock is dropped.
pub struct LockReads {
    path: std::path::PathBuf,
}

impl Drop for LockReads {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let mut restored = match fs::metadata(&self.path) {
            Ok(meta) => meta.permissions(),
            Err(_) => return,
        };
        restored.set_mode(0o644);
        let _ = fs::set_permissions(&self.path, restored);
    }
}

pub fn lock_reads(path: &std::path::Path) -> LockReads {
    use std::os::unix::fs::PermissionsExt as _;
    let mut denied = match fs::metadata(path) {
        Ok(meta) => meta.permissions(),
        Err(err) => panic!("lock_reads: {err}"),
    };
    denied.set_mode(0o200); // write-only: reads fail until it is dropped
    fs::set_permissions(path, denied).unwrap();
    LockReads {
        path: path.to_path_buf(),
    }
}
