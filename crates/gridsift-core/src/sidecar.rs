//! Where derived files live.
//!
//! Sidecars (indexes, later project state) are never written next to the
//! evidence: the source directory may be read-only media or a case folder
//! whose listing is itself evidence. They go to the user's cache directory,
//! keyed by the canonical source path.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::dialect::Dialect;
use crate::hash::hex;

/// Root of gridsift's cache tree (`~/Library/Caches/gridsift`,
/// `~/.cache/gridsift`, `%LOCALAPPDATA%\gridsift`), falling back to the
/// temp directory when the platform has no cache location.
pub fn cache_root() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("gridsift")
}

/// File stem and key of `source` parsed with `dialect`: the canonical path
/// and the parser settings, hashed.
///
/// The dialect is part of the key: an index records where records start,
/// and that depends on the delimiter, quoting and header settings, so a
/// file opened with `--no-header` must not pick up the index that was built
/// with a header; the same goes for the analyses computed over its records.
fn sidecar_key(source: &Path, dialect: Dialect) -> io::Result<(String, String)> {
    let canon = fs::canonicalize(source)?;
    let mut keyed = canon.to_string_lossy().into_owned().into_bytes();
    keyed.push(0);
    keyed.push(dialect.delimiter);
    keyed.push(dialect.quote.unwrap_or(0));
    keyed.push(u8::from(dialect.has_header));
    let key = hex(&blake3::hash(&keyed).as_bytes()[..16]);
    let stem = source
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "source".into());
    Ok((stem, key))
}

/// Location of the sparse index for `source` parsed with `dialect` under
/// the cache tree `root`.
pub fn index_path_in(root: &Path, source: &Path, dialect: Dialect) -> io::Result<PathBuf> {
    let (stem, key) = sidecar_key(source, dialect)?;
    Ok(root.join("index").join(format!("{stem}.{key}.gsix")))
}

/// Default location of the sparse index for `source` parsed with `dialect`.
pub fn default_index_path(source: &Path, dialect: Dialect) -> io::Result<PathBuf> {
    index_path_in(&cache_root(), source, dialect)
}

/// Location of the cached whole-file analyses (column profile, value
/// counts, timelines) of `source` parsed with `dialect` under `root`.
pub fn analysis_path_in(root: &Path, source: &Path, dialect: Dialect) -> io::Result<PathBuf> {
    let (stem, key) = sidecar_key(source, dialect)?;
    Ok(root.join("analysis").join(format!("{stem}.{key}.gsan")))
}

/// Default location of the cached whole-file analyses of `source`.
pub fn default_analysis_path(source: &Path, dialect: Dialect) -> io::Result<PathBuf> {
    analysis_path_in(&cache_root(), source, dialect)
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
        let d = Dialect::default();
        let pa = default_index_path(&a, d).unwrap();
        let pb = default_index_path(&b, d).unwrap();
        assert_eq!(pa, default_index_path(&a, d).unwrap());
        assert_ne!(pa, pb);
        // the same file parsed differently gets its own sidecar
        let no_header = Dialect {
            has_header: false,
            ..d
        };
        assert_ne!(pa, default_index_path(&a, no_header).unwrap());
        assert!(pa.starts_with(cache_root()));
        assert!(
            pa.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("a.csv.")
        );
        assert!(pa.extension().is_some_and(|e| e == "gsix"));
        assert!(default_index_path(&dir.join("missing.csv"), d).is_err());
        // the analyses share the key and sit beside the index tree
        let an = default_analysis_path(&a, d).unwrap();
        assert!(an.extension().is_some_and(|e| e == "gsan"));
        assert_eq!(an.file_stem(), pa.file_stem());
        assert_ne!(an, default_analysis_path(&a, no_header).unwrap());
        assert_eq!(
            index_path_in(Path::new("/x"), &a, d).unwrap(),
            Path::new("/x").join("index").join(pa.file_name().unwrap())
        );
    }
}
