#![allow(dead_code)]

use std::fs;

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
