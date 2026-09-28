//! Read-only access to the source file (the evidence).
//!
//! The file is opened read-only and memory-mapped for random access; bulk
//! sequential passes use positioned reads into a caller-owned buffer, which
//! is cheaper than page-faulting through a mapping on most platforms.
//! Nothing in this crate ever writes to the source.

use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

/// Cheap identity of a source file used to bind sidecars (index, digests,
/// project state) to the bytes they were computed from. Path-independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceId {
    pub size: u64,
    /// Modification time as seconds/nanoseconds since the Unix epoch
    /// (zero if unavailable or before the epoch).
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
}

impl SourceId {
    pub fn from_metadata(meta: &Metadata) -> SourceId {
        let (mtime_secs, mtime_nanos) = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()));
        SourceId {
            size: meta.len(),
            mtime_secs,
            mtime_nanos,
        }
    }

    pub fn mtime(&self) -> Option<SystemTime> {
        if self.mtime_secs == 0 && self.mtime_nanos == 0 {
            None
        } else {
            UNIX_EPOCH.checked_add(std::time::Duration::new(self.mtime_secs, self.mtime_nanos))
        }
    }
}

/// An opened, read-only, memory-mapped source file.
pub struct Source {
    path: PathBuf,
    file: File,
    mmap: Option<Mmap>,
    id: SourceId,
}

impl Source {
    /// Open `path` read-only. Fails if the file cannot be read or mapped.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Source> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        let id = SourceId::from_metadata(&meta);
        let mmap = if id.size == 0 {
            None
        } else {
            // SAFETY: the mapping is read-only. If another process truncates
            // the file while mapped, accesses beyond the new end fault; that is
            // an accepted limitation shared by every mmap-based viewer and is
            // mitigated by `verify_unchanged` checks before long operations.
            Some(unsafe { Mmap::map(&file)? })
        };
        Ok(Source {
            path,
            file,
            mmap,
            id,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn id(&self) -> SourceId {
        self.id
    }

    pub fn len(&self) -> u64 {
        self.id.size
    }

    pub fn is_empty(&self) -> bool {
        self.id.size == 0
    }

    /// The whole file as a byte slice (via the mapping).
    pub fn bytes(&self) -> &[u8] {
        self.mmap.as_deref().unwrap_or(&[])
    }

    /// Bytes of `range`, clamped to the file.
    pub fn slice(&self, start: u64, end: u64) -> &[u8] {
        let b = self.bytes();
        let s = (start.min(self.len())) as usize;
        let e = (end.min(self.len())) as usize;
        &b[s..e.max(s)]
    }

    /// Positioned read: fills `buf` from `offset` until full or EOF.
    /// Returns the number of bytes read (less than `buf.len()` only at EOF).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = read_at_once(&self.file, &mut buf[done..], offset + done as u64)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    /// Hint that the mapping will be scanned front to back (no-op where
    /// `madvise` is unavailable).
    pub fn advise_sequential(&self) {
        #[cfg(unix)]
        if let Some(m) = &self.mmap {
            let _ = m.advise(memmap2::Advice::Sequential);
        }
    }

    /// Hint that the mapping will be accessed at random (viewport use).
    pub fn advise_random(&self) {
        #[cfg(unix)]
        if let Some(m) = &self.mmap {
            let _ = m.advise(memmap2::Advice::Random);
        }
    }

    /// Re-stat the file and report whether its identity still matches the one
    /// observed at open time. A `false` here means cached offsets and digests
    /// can no longer be trusted.
    pub fn verify_unchanged(&self) -> io::Result<bool> {
        let meta = self.file.metadata()?;
        Ok(SourceId::from_metadata(&meta) == self.id)
    }

    /// Fail unless the source still has the identity it was opened with.
    /// This is a metadata check (size and modification time), not a
    /// cryptographic one; it catches another process rewriting the file.
    pub fn ensure_unchanged(&self) -> io::Result<()> {
        if self.verify_unchanged()? {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{} changed since it was opened (size or modification time differ); reopen it",
                self.path.display()
            )))
        }
    }

    /// Refuse a write target that is the evidence itself: by path, and —
    /// when the target exists — by file identity (device and inode on Unix,
    /// size and modification time everywhere). Every file gridsift writes
    /// (exports, manifests, index sidecars and their temporaries) passes
    /// through this check before anything is created.
    pub fn guard_not_source(&self, target: &Path) -> io::Result<()> {
        let refuse = || {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to write over the source file {}",
                    self.path.display()
                ),
            ))
        };
        if let (Ok(a), Ok(b)) = (
            std::fs::canonicalize(&self.path),
            std::fs::canonicalize(target),
        ) {
            if a == b {
                return refuse();
            }
        }
        let Ok(meta) = std::fs::metadata(target) else {
            return Ok(());
        };
        if !meta.is_file() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(mine) = self.file.metadata() {
                if meta.dev() == mine.dev() && meta.ino() == mine.ino() {
                    return refuse();
                }
            }
        }
        if SourceId::from_metadata(&meta) == self.id {
            return refuse();
        }
        Ok(())
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("path", &self.path)
            .field("id", &self.id)
            .finish()
    }
}

#[cfg(unix)]
fn read_at_once(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    loop {
        match file.read_at(buf, offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

#[cfg(windows)]
fn read_at_once(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str, data: &[u8]) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gridsift-src-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn open_map_and_read() {
        let p = temp("basic", b"hello,world\n1,2\n");
        let s = Source::open(&p).unwrap();
        assert_eq!(s.len(), 16);
        assert_eq!(s.bytes(), b"hello,world\n1,2\n");
        assert_eq!(s.slice(6, 11), b"world");
        assert_eq!(s.slice(14, 100), b"2\n");
        let mut buf = [0u8; 5];
        assert_eq!(s.read_at(&mut buf, 6).unwrap(), 5);
        assert_eq!(&buf, b"world");
        assert_eq!(s.read_at(&mut buf, 14).unwrap(), 2);
        assert!(s.verify_unchanged().unwrap());
    }

    #[test]
    fn empty_file() {
        let p = temp("empty", b"");
        let s = Source::open(&p).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.bytes(), b"");
        let mut buf = [0u8; 4];
        assert_eq!(s.read_at(&mut buf, 0).unwrap(), 0);
    }

    #[test]
    fn detects_modification() {
        let p = temp("modified", b"a,b\n");
        let s = Source::open(&p).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"c,d\n")
            .unwrap();
        assert!(!s.verify_unchanged().unwrap());
    }
}
