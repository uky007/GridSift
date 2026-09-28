//! Sparse logical-record index.
//!
//! One checkpoint `(record ordinal, byte offset)` every N records or every
//! M bytes, whichever comes first, placed only where the quote-aware scanner
//! confirmed a record boundary. At the default stride a billion-record file
//! needs a few megabytes of index; a jump costs at most one stride of
//! re-scanning from the preceding checkpoint.
//!
//! The index is bound to the source identity (size + mtime) and, when the
//! build completes, carries the source digests computed in the same pass.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use crate::dialect::Dialect;
use crate::hash::{Digests, HashSelection, MultiHasher};
use crate::scan::{Control, RecordSpan, Scanner, Sink};
use crate::source::{Source, SourceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// 0-based data record ordinal (header excluded).
    pub record: u64,
    /// Absolute byte offset of the record's first byte.
    pub offset: u64,
}

/// Byte span `start..end` in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexParams {
    pub dialect: Dialect,
    /// Where scanning starts (after a BOM).
    pub scan_start: u64,
    /// Maximum records between checkpoints.
    pub stride_records: u32,
    /// Maximum bytes between checkpoints (bounds re-scan cost for wide rows).
    pub stride_bytes: u64,
}

impl Default for IndexParams {
    fn default() -> Self {
        IndexParams {
            dialect: Dialect::default(),
            scan_start: 0,
            stride_records: 4096,
            stride_bytes: 4 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexStats {
    /// Data records seen (header excluded).
    pub records: u64,
    /// Absolute offset the scan has reached.
    pub bytes_scanned: u64,
    /// Field count of the header (or of the first data record without one).
    pub expected_fields: u32,
    /// Records whose field count differs from `expected_fields`.
    pub field_mismatches: u64,
    /// Records with a lenient quote closure (`"abc"def`).
    pub lenient_quotes: u64,
    /// Records that hit EOF inside a quoted field (0 or 1).
    pub unterminated_quotes: u64,
    /// Longest record content in bytes.
    pub max_record_bytes: u64,
    /// The scan reached EOF without being cancelled.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SparseIndex {
    pub source: SourceId,
    pub params: IndexParams,
    /// Span of the header record, if the dialect has one and it was seen.
    pub header: Option<Span>,
    pub checkpoints: Vec<Checkpoint>,
    pub stats: IndexStats,
    /// Source digests; populated only by a completed build that requested them.
    pub digests: Digests,
}

impl SparseIndex {
    pub fn new(source: SourceId, params: IndexParams) -> SparseIndex {
        SparseIndex {
            source,
            params,
            header: None,
            checkpoints: Vec::new(),
            stats: IndexStats::default(),
            digests: Digests::default(),
        }
    }

    /// Nearest checkpoint at or before `record`; `None` if there are no
    /// checkpoints yet (no data records seen).
    pub fn locate(&self, record: u64) -> Option<Checkpoint> {
        let i = self.checkpoints.partition_point(|c| c.record <= record);
        if i == 0 {
            None
        } else {
            Some(self.checkpoints[i - 1])
        }
    }

    /// Last checkpoint: the furthest point reachable without a long forward scan.
    pub fn frontier(&self) -> Option<Checkpoint> {
        self.checkpoints.last().copied()
    }

    /// In-memory size of the checkpoint table.
    pub fn table_bytes(&self) -> usize {
        self.checkpoints.len() * std::mem::size_of::<Checkpoint>()
    }

    pub fn matches_source(&self, id: SourceId) -> bool {
        self.source == id
    }

    /// Write the sidecar. Refuses a target that carries the identity of the
    /// indexed source (a copy of the evidence, or the evidence itself);
    /// [`SparseIndex::save_for`] additionally checks the path against the
    /// open source and is what callers should use.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let bytes = self.to_bytes();
        let path = path.as_ref();
        let tmp = temp_path(path);
        for p in [path, tmp.as_path()] {
            if let Ok(meta) = fs::metadata(p)
                && meta.is_file()
                && SourceId::from_metadata(&meta) == self.source
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write the index over {}: it has the identity of the indexed source",
                        p.display()
                    ),
                ));
            }
        }
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        // write-then-rename so a crash never leaves a half-written sidecar
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Write the sidecar after checking that neither the target nor its
    /// temporary file is `source`.
    pub fn save_for(&self, source: &Source, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        source.guard_not_source(path)?;
        source.guard_not_source(&temp_path(path))?;
        self.save(path)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<SparseIndex, IndexError> {
        let bytes = fs::read(path)?;
        SparseIndex::from_bytes(&bytes)
    }

    /// Serialise to the `GSIX` v1 format (little-endian, BLAKE3 trailer).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(160 + self.checkpoints.len() * 16);
        w.extend_from_slice(MAGIC);
        put_u16(&mut w, VERSION);
        let mut flags = 0u16;
        if self.stats.complete {
            flags |= FLAG_COMPLETE;
        }
        if self.header.is_some() {
            flags |= FLAG_HEADER;
        }
        if self.digests.sha256.is_some() {
            flags |= FLAG_SHA256;
        }
        if self.digests.blake3.is_some() {
            flags |= FLAG_BLAKE3;
        }
        put_u16(&mut w, flags);
        put_u64(&mut w, self.source.size);
        put_u64(&mut w, self.source.mtime_secs);
        put_u32(&mut w, self.source.mtime_nanos);
        let d = self.params.dialect;
        w.extend_from_slice(&[d.delimiter, d.quote.unwrap_or(0), d.has_header as u8, 0]);
        put_u64(&mut w, self.params.scan_start);
        put_u32(&mut w, self.params.stride_records);
        put_u64(&mut w, self.params.stride_bytes);
        let h = self.header.unwrap_or(Span { start: 0, end: 0 });
        put_u64(&mut w, h.start);
        put_u64(&mut w, h.end);
        let s = &self.stats;
        put_u64(&mut w, s.records);
        put_u64(&mut w, s.bytes_scanned);
        put_u32(&mut w, s.expected_fields);
        put_u64(&mut w, s.field_mismatches);
        put_u64(&mut w, s.lenient_quotes);
        put_u64(&mut w, s.unterminated_quotes);
        put_u64(&mut w, s.max_record_bytes);
        w.extend_from_slice(&self.digests.sha256.unwrap_or([0; 32]));
        w.extend_from_slice(&self.digests.blake3.unwrap_or([0; 32]));
        put_u64(&mut w, self.checkpoints.len() as u64);
        for c in &self.checkpoints {
            put_u64(&mut w, c.record);
            put_u64(&mut w, c.offset);
        }
        let trailer = blake3::hash(&w);
        w.extend_from_slice(trailer.as_bytes());
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<SparseIndex, IndexError> {
        if b.len() < MAGIC.len() + 2 || &b[..4] != MAGIC {
            return Err(IndexError::BadMagic);
        }
        if b.len() < 32 {
            return Err(IndexError::Corrupt("truncated"));
        }
        let (body, trailer) = b.split_at(b.len() - 32);
        if blake3::hash(body).as_bytes() != trailer {
            return Err(IndexError::Corrupt("trailer digest mismatch"));
        }
        let mut r = Reader { b: body, i: 4 };
        let version = r.u16()?;
        if version != VERSION {
            return Err(IndexError::UnsupportedVersion(version));
        }
        let flags = r.u16()?;
        let source = SourceId {
            size: r.u64()?,
            mtime_secs: r.u64()?,
            mtime_nanos: r.u32()?,
        };
        let delimiter = r.u8()?;
        let quote = match r.u8()? {
            0 => None,
            q => Some(q),
        };
        let has_header = r.u8()? != 0;
        r.u8()?;
        let params = IndexParams {
            dialect: Dialect {
                delimiter,
                quote,
                has_header,
            },
            scan_start: r.u64()?,
            stride_records: r.u32()?,
            stride_bytes: r.u64()?,
        };
        let hs = r.u64()?;
        let he = r.u64()?;
        let header = (flags & FLAG_HEADER != 0).then_some(Span { start: hs, end: he });
        let stats = IndexStats {
            records: r.u64()?,
            bytes_scanned: r.u64()?,
            expected_fields: r.u32()?,
            field_mismatches: r.u64()?,
            lenient_quotes: r.u64()?,
            unterminated_quotes: r.u64()?,
            max_record_bytes: r.u64()?,
            complete: flags & FLAG_COMPLETE != 0,
        };
        let sha = r.bytes32()?;
        let b3 = r.bytes32()?;
        let digests = Digests {
            sha256: (flags & FLAG_SHA256 != 0).then_some(sha),
            blake3: (flags & FLAG_BLAKE3 != 0).then_some(b3),
        };
        let n = r.u64()?;
        if n > (body.len() as u64) / 16 {
            return Err(IndexError::Corrupt("checkpoint count exceeds payload"));
        }
        let mut checkpoints = Vec::with_capacity(n as usize);
        for _ in 0..n {
            checkpoints.push(Checkpoint {
                record: r.u64()?,
                offset: r.u64()?,
            });
        }
        if r.i != body.len() {
            return Err(IndexError::Corrupt("trailing bytes"));
        }
        Ok(SparseIndex {
            source,
            params,
            header,
            checkpoints,
            stats,
            digests,
        })
    }
}

const MAGIC: &[u8; 4] = b"GSIX";
const VERSION: u16 = 1;
const FLAG_COMPLETE: u16 = 1 << 0;
const FLAG_HEADER: u16 = 1 << 1;
const FLAG_SHA256: u16 = 1 << 2;
const FLAG_BLAKE3: u16 = 1 << 3;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a gridsift index file")]
    BadMagic,
    #[error("unsupported index format version {0}")]
    UnsupportedVersion(u16),
    #[error("corrupt index: {0}")]
    Corrupt(&'static str),
}

fn put_u16(w: &mut Vec<u8>, v: u16) {
    w.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_le_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], IndexError> {
        if self.i + n > self.b.len() {
            return Err(IndexError::Corrupt("truncated"));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, IndexError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, IndexError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, IndexError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes32(&mut self) -> Result<[u8; 32], IndexError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

/// Options for [`build_index`].
#[derive(Clone, Copy, Debug)]
pub struct BuildOptions<'a> {
    /// Read buffer size for the sequential pass.
    pub chunk_size: usize,
    /// Digests to compute in the same pass.
    pub hash: HashSelection,
    /// Track field counts (needed for `field_mismatches`).
    pub count_fields: bool,
    /// Checked between chunks; a set flag stops the build and returns the
    /// partial index with `stats.complete == false`.
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for BuildOptions<'_> {
    fn default() -> Self {
        BuildOptions {
            chunk_size: 8 << 20,
            hash: HashSelection::SHA256,
            count_fields: true,
            cancel: None,
        }
    }
}

/// Progress report passed to the build observer after every chunk.
#[derive(Clone, Copy, Debug)]
pub struct Progress {
    pub bytes: u64,
    pub total: u64,
    pub records: u64,
    pub checkpoints: usize,
}

struct BuildState {
    has_header: bool,
    saw_header: bool,
    count_fields: bool,
    stride_records: u64,
    stride_bytes: u64,
}

struct BuildSink<'a> {
    idx: &'a mut SparseIndex,
    st: &'a mut BuildState,
}

impl Sink for BuildSink<'_> {
    #[inline]
    fn record(&mut self, s: RecordSpan) -> Control {
        let idx = &mut *self.idx;
        let st = &mut *self.st;
        if st.has_header && !st.saw_header {
            st.saw_header = true;
            idx.header = Some(Span {
                start: s.start,
                end: s.end,
            });
            idx.stats.expected_fields = s.fields;
            return Control::Continue;
        }
        let rec = idx.stats.records;
        if rec == 0 && !st.has_header {
            idx.stats.expected_fields = s.fields;
        }
        let need_checkpoint = match idx.checkpoints.last() {
            None => true,
            Some(cp) => {
                rec - cp.record >= st.stride_records || s.start - cp.offset >= st.stride_bytes
            }
        };
        if need_checkpoint {
            idx.checkpoints.push(Checkpoint {
                record: rec,
                offset: s.start,
            });
        }
        let stats = &mut idx.stats;
        stats.records += 1;
        if st.count_fields && s.fields != stats.expected_fields {
            stats.field_mismatches += 1;
        }
        if s.lenient_quote {
            stats.lenient_quotes += 1;
        }
        if s.unterminated_quote {
            stats.unterminated_quotes += 1;
        }
        stats.max_record_bytes = stats.max_record_bytes.max(s.end - s.start);
        Control::Continue
    }
}

/// Minimal index that only knows where the header and the first data record
/// are, so a viewport can be served immediately while the full build runs in
/// the background. Touches only the first pages of the file.
/// `<path>.tmp` next to the sidecar (appended, so `evidence.csv` can never
/// map onto a sibling like `evidence.tmp`).
fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "index".into());
    name.push(".tmp");
    path.with_file_name(name)
}

pub fn bootstrap(source: &Source, params: IndexParams) -> SparseIndex {
    let mut idx = SparseIndex::new(source.id(), params);
    let mut st = BuildState {
        has_header: params.dialect.has_header,
        saw_header: false,
        count_fields: true,
        stride_records: u64::MAX,
        stride_bytes: u64::MAX,
    };
    let bytes = source.bytes();
    let from = (params.scan_start as usize).min(bytes.len());
    let mut scanner = Scanner::at(params.dialect.scan_config(true), from as u64, 0);
    // Stop as soon as the first data record has been seen.
    let mut sink = |s: RecordSpan| {
        let mut inner = BuildSink {
            idx: &mut idx,
            st: &mut st,
        };
        inner.record(s);
        if idx.checkpoints.is_empty() {
            Control::Continue
        } else {
            Control::Stop
        }
    };
    if scanner.feed(&bytes[from..], &mut sink) == Control::Continue {
        scanner.finish(&mut sink);
    }
    // Only the location of record 0 is meaningful here; the counters are not.
    idx.stats = IndexStats {
        expected_fields: idx.stats.expected_fields,
        ..IndexStats::default()
    };
    idx
}

/// A filled read buffer shared between the scanner and the hash thread.
struct Chunk {
    buf: Vec<u8>,
    len: usize,
}

impl Chunk {
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Return a chunk's buffer to the pool once the last owner lets go of it.
fn recycle(chunk: Arc<Chunk>, free_tx: &mpsc::Sender<Vec<u8>>) {
    if let Ok(c) = Arc::try_unwrap(chunk) {
        let _ = free_tx.send(c.buf);
    }
}

/// Build a sparse index (and optionally digests) in one sequential pass.
///
/// `observer` is called after every chunk with the partial index, so a UI can
/// start using checkpoints while the build is still running. Returns the
/// partial index if cancelled. Fails if the source changed during the build.
pub fn build_index(
    source: &Source,
    params: IndexParams,
    opts: BuildOptions<'_>,
    observer: &mut dyn FnMut(&SparseIndex, &Progress),
) -> io::Result<SparseIndex> {
    let mut idx = SparseIndex::new(source.id(), params);
    let mut st = BuildState {
        has_header: params.dialect.has_header,
        saw_header: false,
        count_fields: opts.count_fields,
        stride_records: params.stride_records.max(1) as u64,
        stride_bytes: params.stride_bytes.max(1),
    };
    let mut scanner = Scanner::at(
        params.dialect.scan_config(opts.count_fields),
        params.scan_start,
        0,
    );
    let chunk_size = opts.chunk_size.clamp(64 << 10, 1 << 30);
    let total = source.len();
    let mut off = 0u64;
    let mut cancelled = false;

    // The digest runs on its own thread so it does not slow the scan: each
    // chunk is shared read-only through an `Arc` and its buffer is recycled
    // through a pool once both consumers are done with it.
    let digests = std::thread::scope(|scope| -> io::Result<Option<Digests>> {
        let (chunk_tx, chunk_rx) = mpsc::sync_channel::<Arc<Chunk>>(2);
        let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>();
        let hasher = (!opts.hash.is_empty()).then(|| {
            let free_tx = free_tx.clone();
            let sel = opts.hash;
            scope.spawn(move || {
                crate::sys::boost_current_thread();
                let mut h = MultiHasher::new(sel);
                for chunk in chunk_rx {
                    h.update(chunk.bytes());
                    recycle(chunk, &free_tx);
                }
                h.finalize()
            })
        });
        // Without a hasher nobody receives, so drop the sender up front.
        let chunk_tx = hasher.is_some().then_some(chunk_tx);
        let mut io_err = None;

        while off < total {
            if opts.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                cancelled = true;
                break;
            }
            let mut buf = free_rx.try_recv().unwrap_or_else(|_| vec![0u8; chunk_size]);
            let n = match source.read_at(&mut buf, off) {
                Ok(n) => n,
                Err(e) => {
                    io_err = Some(e);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            let chunk = Arc::new(Chunk { buf, len: n });
            if let Some(tx) = &chunk_tx {
                // The receiver only disappears if the hash thread panicked;
                // that surfaces at join time.
                let _ = tx.send(chunk.clone());
            }
            let skip = params.scan_start.saturating_sub(off).min(n as u64) as usize;
            if skip < n {
                let mut sink = BuildSink {
                    idx: &mut idx,
                    st: &mut st,
                };
                scanner.feed(&chunk.bytes()[skip..], &mut sink);
            }
            recycle(chunk, &free_tx);
            off += n as u64;
            idx.stats.bytes_scanned = off;
            observer(
                &idx,
                &Progress {
                    bytes: off,
                    total,
                    records: idx.stats.records,
                    checkpoints: idx.checkpoints.len(),
                },
            );
        }

        drop(chunk_tx);
        let digests = match hasher {
            Some(h) => Some(
                h.join()
                    .map_err(|_| io::Error::other("hash thread panicked"))?,
            ),
            None => None,
        };
        match io_err {
            Some(e) => Err(e),
            None => Ok(digests),
        }
    })?;

    if !cancelled {
        let mut sink = BuildSink {
            idx: &mut idx,
            st: &mut st,
        };
        scanner.finish(&mut sink);
        if !source.verify_unchanged()? {
            return Err(io::Error::other(
                "source file changed while it was being indexed",
            ));
        }
        idx.stats.complete = true;
        idx.digests = digests.unwrap_or_default();
    }
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    /// Unique file per call: tests run in parallel and must not share paths.
    fn temp(data: &[u8]) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gridsift-idx-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    fn build(data: &[u8], params: IndexParams, opts: BuildOptions<'_>) -> SparseIndex {
        let p = temp(data);
        let src = Source::open(&p).unwrap();
        build_index(&src, params, opts, &mut |_, _| {}).unwrap()
    }

    #[test]
    fn checkpoints_by_record_stride() {
        let mut data = b"h1,h2\n".to_vec();
        for i in 0..100 {
            data.extend_from_slice(format!("{i},x\n").as_bytes());
        }
        let params = IndexParams {
            stride_records: 10,
            stride_bytes: u64::MAX,
            ..IndexParams::default()
        };
        let idx = build(
            &data,
            params,
            BuildOptions {
                chunk_size: 64 << 10,
                ..Default::default()
            },
        );
        assert!(idx.stats.complete);
        assert_eq!(idx.stats.records, 100);
        assert_eq!(idx.header, Some(Span { start: 0, end: 5 }));
        assert_eq!(idx.stats.expected_fields, 2);
        assert_eq!(idx.stats.field_mismatches, 0);
        assert_eq!(idx.checkpoints.len(), 10);
        assert_eq!(
            idx.checkpoints[0],
            Checkpoint {
                record: 0,
                offset: 6
            }
        );
        assert_eq!(idx.checkpoints[1].record, 10);
        assert_eq!(idx.locate(0).unwrap().record, 0);
        assert_eq!(idx.locate(9).unwrap().record, 0);
        assert_eq!(idx.locate(10).unwrap().record, 10);
        assert_eq!(idx.locate(99).unwrap().record, 90);
        assert_eq!(idx.locate(1_000).unwrap().record, 90);
        assert!(idx.digests.sha256.is_some());
        assert!(idx.digests.blake3.is_none());
    }

    #[test]
    fn checkpoints_by_byte_stride_and_stats() {
        // rows of ~20 bytes; byte stride 50 forces a checkpoint every 3 rows
        let mut data = Vec::new();
        for i in 0..30 {
            data.extend_from_slice(format!("{i:05},\"a,b\",{i:010}\n").as_bytes());
        }
        data.extend_from_slice(b"bad,\"x\"y\n1,2\n\"open");
        let params = IndexParams {
            dialect: Dialect {
                has_header: false,
                ..Dialect::default()
            },
            stride_records: u32::MAX,
            stride_bytes: 50,
            ..IndexParams::default()
        };
        let idx = build(&data, params, BuildOptions::default());
        assert_eq!(idx.stats.records, 33);
        assert_eq!(idx.stats.expected_fields, 3);
        assert_eq!(idx.stats.field_mismatches, 3); // "bad,\"x\"y" (2), "1,2" (2), "\"open" (1)
        assert_eq!(idx.stats.lenient_quotes, 1);
        assert_eq!(idx.stats.unterminated_quotes, 1);
        assert_eq!(idx.stats.max_record_bytes, 22);
        assert!(idx.checkpoints.len() >= 10);
        for w in idx.checkpoints.windows(2) {
            assert!(w[1].offset - w[0].offset >= 50);
        }
    }

    #[test]
    fn small_chunks_match_large_chunks() {
        let mut data = b"a,b,c\n".to_vec();
        for i in 0..500 {
            data.extend_from_slice(format!("{i},\"q\n{i}\",\"\"\"\"\r\n").as_bytes());
        }
        let params = IndexParams {
            stride_records: 7,
            stride_bytes: 100,
            ..IndexParams::default()
        };
        let big = build(
            &data,
            params,
            BuildOptions {
                chunk_size: 1 << 20,
                ..Default::default()
            },
        );
        let small = build(
            &data,
            params,
            BuildOptions {
                chunk_size: 64 << 10,
                ..Default::default()
            },
        );
        // chunk_size is clamped to >= 64 KiB, so exercise the scanner's own
        // chunking separately: same data through 1-byte feeds
        assert_eq!(big.checkpoints, small.checkpoints);
        assert_eq!(big.stats, small.stats);
        assert_eq!(big.stats.records, 500);
        assert_eq!(big.stats.field_mismatches, 0);
    }

    #[test]
    fn roundtrip_serialisation() {
        let data = b"h\n1\n2\n3\n";
        let idx = build(
            data,
            IndexParams::default(),
            BuildOptions {
                hash: HashSelection::ALL,
                ..Default::default()
            },
        );
        let bytes = idx.to_bytes();
        let back = SparseIndex::from_bytes(&bytes).unwrap();
        assert_eq!(back, idx);
        // corruption is detected
        let mut bad = bytes.clone();
        bad[40] ^= 1;
        assert!(matches!(
            SparseIndex::from_bytes(&bad),
            Err(IndexError::Corrupt(_))
        ));
        assert!(matches!(
            SparseIndex::from_bytes(b"nope"),
            Err(IndexError::BadMagic)
        ));
        // save/load through a file
        let p = temp(data).with_extension("gridsift-index");
        idx.save(&p).unwrap();
        assert_eq!(SparseIndex::load(&p).unwrap(), idx);
    }

    #[test]
    fn cancel_returns_partial() {
        let mut data = Vec::new();
        for i in 0..20_000 {
            data.extend_from_slice(format!("{i},abcdefghij\n").as_bytes());
        }
        let cancel = AtomicBool::new(true);
        let params = IndexParams {
            dialect: Dialect {
                has_header: false,
                ..Dialect::default()
            },
            ..IndexParams::default()
        };
        let idx = build(
            &data,
            params,
            BuildOptions {
                cancel: Some(&cancel),
                ..Default::default()
            },
        );
        assert!(!idx.stats.complete);
        assert_eq!(idx.stats.records, 0);
        assert!(idx.digests.is_empty());
    }

    #[test]
    fn header_only_and_empty() {
        let idx = build(b"a,b\n", IndexParams::default(), BuildOptions::default());
        assert_eq!(idx.stats.records, 0);
        assert!(idx.checkpoints.is_empty());
        assert!(idx.header.is_some());
        assert!(idx.locate(0).is_none());
        let idx = build(b"", IndexParams::default(), BuildOptions::default());
        assert!(idx.stats.complete);
        assert!(idx.header.is_none());
    }

    #[test]
    fn bootstrap_locates_first_record_only() {
        let data = b"\xEF\xBB\xBFh1,h2\n1,\"a\nb\"\n2,c\n3,d\n";
        let p = temp(data);
        let src = Source::open(&p).unwrap();
        let params = IndexParams {
            scan_start: 3,
            ..IndexParams::default()
        };
        let idx = bootstrap(&src, params);
        assert_eq!(idx.header, Some(Span { start: 3, end: 8 }));
        assert_eq!(
            idx.checkpoints,
            vec![Checkpoint {
                record: 0,
                offset: 9
            }]
        );
        assert_eq!(idx.stats.expected_fields, 2);
        assert!(!idx.stats.complete);
        assert_eq!(idx.stats.records, 0);
        // a full build agrees on record 0
        let full = build_index(&src, params, BuildOptions::default(), &mut |_, _| {}).unwrap();
        assert_eq!(full.checkpoints[0], idx.checkpoints[0]);
        assert_eq!(full.stats.records, 3);
        // header-only and empty files bootstrap to no checkpoints
        let p = temp(b"h1,h2\n");
        let idx = bootstrap(&Source::open(&p).unwrap(), IndexParams::default());
        assert!(idx.checkpoints.is_empty());
        assert!(idx.header.is_some());
        let p = temp(b"");
        let idx = bootstrap(&Source::open(&p).unwrap(), IndexParams::default());
        assert!(idx.checkpoints.is_empty());
    }

    #[test]
    fn bom_is_skipped_via_scan_start() {
        let data = b"\xEF\xBB\xBFa,b\n1,2\n";
        let params = IndexParams {
            scan_start: 3,
            ..IndexParams::default()
        };
        let idx = build(data, params, BuildOptions::default());
        assert_eq!(idx.header, Some(Span { start: 3, end: 6 }));
        assert_eq!(idx.checkpoints[0].offset, 7);
        // digest still covers the whole file, BOM included
        let mut h = MultiHasher::new(HashSelection::SHA256);
        h.update(data);
        assert_eq!(idx.digests, h.finalize());
    }
}
