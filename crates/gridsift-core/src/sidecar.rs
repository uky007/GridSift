//! Where derived files live.
//!
//! Sidecars (indexes, later project state) are never written next to the
//! evidence: the source directory may be read-only media or a case folder
//! whose listing is itself evidence. They go to the user's cache directory,
//! keyed by the canonical source path.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::hex;

/// Root of gridsift's cache tree (`~/Library/Caches/gridsift`,
/// `~/.cache/gridsift`, `%LOCALAPPDATA%\gridsift`), falling back to the
/// temp directory when the platform has no cache location.
pub fn cache_root() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("gridsift")
}

/// Default location of the sparse index for `source`.
pub fn default_index_path(source: &Path) -> io::Result<PathBuf> {
    let canon = fs::canonicalize(source)?;
    let key = hex(&blake3::hash(canon.to_string_lossy().as_bytes()).as_bytes()[..16]);
    let stem = source
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "source".into());
    Ok(cache_root()
        .join("index")
        .join(format!("{stem}.{key}.gsix")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_path_is_stable_and_keyed_by_path() {
        let dir = std::env::temp_dir().join(format!("gridsift-sidecar-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.csv");
        let b = dir.join("b.csv");
        fs::write(&a, b"x\n").unwrap();
        fs::write(&b, b"x\n").unwrap();
        let pa = default_index_path(&a).unwrap();
        let pb = default_index_path(&b).unwrap();
        assert_eq!(pa, default_index_path(&a).unwrap());
        assert_ne!(pa, pb);
        assert!(pa.starts_with(cache_root()));
        assert!(
            pa.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("a.csv.")
        );
        assert!(pa.extension().is_some_and(|e| e == "gsix"));
        assert!(default_index_path(&dir.join("missing.csv")).is_err());
    }
}
