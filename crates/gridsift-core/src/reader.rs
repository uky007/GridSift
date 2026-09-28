//! Viewport access: locate a window of records by ordinal using the sparse
//! index, re-scanning at most one stride from the nearest checkpoint.

use std::borrow::Cow;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::index::{Checkpoint, SparseIndex};
use crate::record::split_fields;
use crate::scan::{Control, RecordSpan, Scanner};
use crate::source::Source;

/// A data record located in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Located {
    /// 0-based data record ordinal.
    pub record: u64,
    pub start: u64,
    pub end: u64,
    pub fields: u32,
    pub lenient_quote: bool,
    pub unterminated_quote: bool,
}

impl From<RecordSpan> for Located {
    fn from(s: RecordSpan) -> Self {
        Located {
            record: s.ordinal,
            start: s.start,
            end: s.end,
            fields: s.fields,
            lenient_quote: s.lenient_quote,
            unterminated_quote: s.unterminated_quote,
        }
    }
}

impl Located {
    /// Raw content bytes of the record (terminator excluded).
    pub fn raw<'s>(&self, source: &'s Source) -> &'s [u8] {
        source.slice(self.start, self.end)
    }

    /// Split the record into fields according to the index's dialect.
    pub fn fields<'s>(
        &self,
        source: &'s Source,
        index: &SparseIndex,
        out: &mut Vec<Cow<'s, [u8]>>,
    ) {
        let d = index.params.dialect;
        split_fields(self.raw(source), d.delimiter, d.quote, out);
    }
}

/// Locate records `first .. first + count` (fewer at EOF). Starts from the
/// nearest checkpoint at or before `first`; if `first` lies beyond the indexed
/// frontier the scan simply continues forward, so this is correct but slow for
/// far jumps into an unfinished index.
pub fn locate_records(
    source: &Source,
    index: &SparseIndex,
    first: u64,
    count: usize,
) -> Vec<Located> {
    let mut out = Vec::with_capacity(count.min(4096));
    if count == 0 {
        return out;
    }
    let Some(cp) = index.locate(first) else {
        return out;
    };
    let cfg = index.params.dialect.scan_config(true);
    let mut scanner = Scanner::at(cfg, cp.offset, cp.record);
    let last = first.saturating_add(count as u64 - 1);
    let mut sink = |s: RecordSpan| {
        if s.ordinal >= first {
            out.push(Located::from(s));
        }
        if s.ordinal >= last {
            Control::Stop
        } else {
            Control::Continue
        }
    };
    let bytes = source.bytes();
    let from = (cp.offset as usize).min(bytes.len());
    if scanner.feed(&bytes[from..], &mut sink) == Control::Continue {
        scanner.finish(&mut sink);
    }
    out
}

/// Locate an arbitrary set of records given as a sorted, de-duplicated list
/// of ordinals. Ordinals that share a checkpoint are served by one scan, so a
/// filtered view fetching scattered rows costs one stride per checkpoint
/// touched rather than per row.
pub fn locate_many(source: &Source, index: &SparseIndex, ordinals: &[u64]) -> Vec<Located> {
    let mut out = Vec::with_capacity(ordinals.len());
    let bytes = source.bytes();
    let cfg = index.params.dialect.scan_config(true);
    let mut i = 0;
    while i < ordinals.len() {
        let Some(cp) = index.locate(ordinals[i]) else {
            break;
        };
        // this group: ordinals served by `cp` (before the next checkpoint)
        let limit = index
            .checkpoints
            .iter()
            .find(|c| c.record > cp.record)
            .map_or(u64::MAX, |c| c.record);
        let mut j = i;
        while j < ordinals.len() && ordinals[j] < limit {
            j += 1;
        }
        let group = &ordinals[i..j];
        let last = *group.last().expect("non-empty group");
        let mut want = 0usize;
        let mut scanner = Scanner::at(cfg, cp.offset, cp.record);
        let mut sink = |s: RecordSpan| {
            while want < group.len() && group[want] < s.ordinal {
                want += 1;
            }
            if want < group.len() && group[want] == s.ordinal {
                out.push(Located::from(s));
                want += 1;
            }
            if s.ordinal >= last {
                Control::Stop
            } else {
                Control::Continue
            }
        };
        let from = (cp.offset as usize).min(bytes.len());
        if scanner.feed(&bytes[from..], &mut sink) == Control::Continue {
            scanner.finish(&mut sink);
        }
        i = j;
    }
    out
}

/// A stretch of the file to stream: from a checkpoint up to `end` (an offset
/// that is a record boundary, or EOF).
#[derive(Clone, Copy, Debug)]
pub struct StreamRange {
    pub from: Checkpoint,
    pub end: u64,
    pub chunk_size: usize,
}

/// Stream every record from checkpoint `from` to EOF in order, reading the
/// file sequentially in `chunk_size` blocks (bounded memory, read-ahead
/// friendly). `f` gets each record's span and exact content bytes; return
/// [`Control::Stop`] to end early. Returns `Ok(false)` if the cancel flag
/// stopped the stream.
pub fn stream_records(
    source: &Source,
    index: &SparseIndex,
    from: Checkpoint,
    chunk_size: usize,
    cancel: Option<&AtomicBool>,
    f: &mut dyn FnMut(RecordSpan, &[u8]) -> Control,
) -> io::Result<bool> {
    let range = StreamRange {
        from,
        end: source.len(),
        chunk_size,
    };
    stream_records_range(source, index, range, cancel, &mut |_| {}, f)
}

/// Like [`stream_records`], but over a byte range that ends at a record
/// boundary. `progress` receives the bytes consumed after each chunk.
pub fn stream_records_range(
    source: &Source,
    index: &SparseIndex,
    range: StreamRange,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(u64),
    f: &mut dyn FnMut(RecordSpan, &[u8]) -> Control,
) -> io::Result<bool> {
    let cfg = index.params.dialect.scan_config(false);
    let total = source.len();
    let end_at = range.end.min(total);
    let mut pos = range.from.offset.min(end_at);
    let mut scanner = Scanner::at(cfg, pos, range.from.record);
    let chunk_size = range.chunk_size.clamp(64 << 10, 1 << 30);
    let mut buf = vec![0u8; chunk_size];
    let mut stopped = false;
    while pos < end_at && !stopped {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Ok(false);
        }
        let want = ((end_at - pos) as usize).min(chunk_size);
        let n = source.read_at(&mut buf[..want], pos)?;
        if n == 0 {
            break;
        }
        let end = pos + n as u64;
        let chunk = &buf[..n];
        let mut sink = |sp: RecordSpan| {
            // a record that began in an earlier chunk comes from the mapping
            let bytes = if sp.start >= pos {
                &chunk[(sp.start - pos) as usize..(sp.end - pos) as usize]
            } else {
                source.slice(sp.start, sp.end)
            };
            f(sp, bytes)
        };
        // only EOF can leave a record unterminated; a range end is a boundary
        stopped = scanner.feed(chunk, &mut sink) == Control::Stop
            || (end >= total && scanner.finish(&mut sink) == Control::Stop);
        progress(n as u64);
        pos = end;
    }
    Ok(true)
}

/// The header record's fields, if the index recorded a header.
pub fn header_fields<'s>(source: &'s Source, index: &SparseIndex) -> Option<Vec<Cow<'s, [u8]>>> {
    let h = index.header?;
    let d = index.params.dialect;
    let mut out = Vec::new();
    split_fields(source.slice(h.start, h.end), d.delimiter, d.quote, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::Dialect;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use std::io::Write as _;

    fn fixture(rows: usize, stride: u32) -> (Source, SparseIndex) {
        let dir = std::env::temp_dir().join(format!(
            "gridsift-rd-{}-{rows}-{stride}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"id,text\n").unwrap();
        for i in 0..rows {
            // every 7th row has a quoted embedded newline
            if i % 7 == 0 {
                write!(f, "{i},\"line1\nline2 {i}\"\r\n").unwrap();
            } else {
                writeln!(f, "{i},row {i}").unwrap();
            }
        }
        drop(f);
        let src = Source::open(&p).unwrap();
        let params = IndexParams {
            dialect: Dialect::default(),
            stride_records: stride,
            stride_bytes: u64::MAX,
            scan_start: 0,
        };
        let idx = build_index(&src, params, BuildOptions::default(), &mut |_, _| {}).unwrap();
        (src, idx)
    }

    #[test]
    fn windows_from_various_checkpoints() {
        let (src, idx) = fixture(1000, 16);
        assert_eq!(idx.stats.records, 1000);
        assert_eq!(
            header_fields(&src, &idx).unwrap(),
            vec![b"id".as_slice(), b"text".as_slice()]
        );
        let mut fields = Vec::new();
        for &first in &[0u64, 1, 15, 16, 17, 500, 998, 999] {
            let recs = locate_records(&src, &idx, first, 5);
            let expect = (5u64).min(1000 - first) as usize;
            assert_eq!(recs.len(), expect, "first={first}");
            for (k, r) in recs.iter().enumerate() {
                assert_eq!(r.record, first + k as u64);
                r.fields(&src, &idx, &mut fields);
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].as_ref(), r.record.to_string().as_bytes());
                if r.record % 7 == 0 {
                    assert!(fields[1].starts_with(b"line1\nline2"));
                }
            }
        }
        assert!(locate_records(&src, &idx, 1000, 5).is_empty());
        assert!(locate_records(&src, &idx, 5, 0).is_empty());
    }

    #[test]
    fn beyond_frontier_still_correct() {
        let (src, mut idx) = fixture(300, 8);
        // pretend the build stopped early: keep only the first 3 checkpoints
        idx.checkpoints.truncate(3);
        let recs = locate_records(&src, &idx, 250, 3);
        assert_eq!(
            recs.iter().map(|r| r.record).collect::<Vec<_>>(),
            vec![250, 251, 252]
        );
    }
}
