//! Literal / regex search over all records, producing the set of matching
//! record ordinals.
//!
//! The scan is parallel: the sparse index provides verified record
//! boundaries with known ordinals, so the file is cut at checkpoints into
//! independent ranges that worker threads process out of order. Inside a
//! range, matching runs over raw bytes in large slices with `memmem` or the
//! `regex` crate (both linear-time), and hits are attributed to records
//! found by the same quote-aware scanner used everywhere else. Only records
//! that straddle a slice boundary, or queries that need field semantics, are
//! evaluated one record at a time.
//!
//! Results accumulate in a compressed bitmap ([`MatchSet`]) that supports
//! `select`/`rank`, so a filtered view can address "the k-th match" without
//! materialising a list.

use std::borrow::Cow;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use memchr::memmem;
use roaring::RoaringTreemap;

use crate::dialect::Dialect;
use crate::index::SparseIndex;
use crate::record::split_fields;
use crate::scan::{Control, RecordSpan, ScanConfig, Scanner};
use crate::source::Source;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    /// Substring of the record (or of a chosen column's value).
    Literal,
    /// Regular expression over the record (or a column's value).
    Regex,
    /// A whole field equal to the pattern: `10.0.0.1` does not select
    /// `10.0.0.10`. With `columns` unset, any field may match. The pattern
    /// may be empty to select empty fields. This is what a value-count
    /// pivot uses.
    Exact,
}

/// A search request. Serialisable so it can be recorded verbatim in a
/// provenance manifest and replayed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchQuery {
    pub pattern: String,
    pub kind: PatternKind,
    pub case_insensitive: bool,
    /// Restrict matching to these 0-based columns; `None` matches against the
    /// raw record bytes.
    pub columns: Option<Vec<usize>>,
    /// Select the records that do *not* match.
    pub invert: bool,
}

impl SearchQuery {
    pub fn literal(pattern: impl Into<String>) -> SearchQuery {
        SearchQuery {
            pattern: pattern.into(),
            kind: PatternKind::Literal,
            case_insensitive: false,
            columns: None,
            invert: false,
        }
    }

    pub fn regex(pattern: impl Into<String>) -> SearchQuery {
        SearchQuery {
            kind: PatternKind::Regex,
            ..SearchQuery::literal(pattern)
        }
    }

    /// Whole-field equality in `column`.
    pub fn exact(pattern: impl Into<String>, column: Option<usize>) -> SearchQuery {
        SearchQuery {
            kind: PatternKind::Exact,
            columns: column.map(|c| vec![c]),
            ..SearchQuery::literal(pattern)
        }
    }

    /// Compile for a given dialect. Regex syntax errors are reported as text.
    pub fn compile(&self, dialect: Dialect) -> Result<Compiled, String> {
        if self.pattern.is_empty() && self.kind != PatternKind::Exact {
            return Err("empty pattern".into());
        }
        let matcher = match (self.kind, self.case_insensitive) {
            (PatternKind::Literal, false) => Matcher::Literal(Box::new(
                memmem::Finder::new(self.pattern.as_bytes()).into_owned(),
            )),
            (PatternKind::Literal, true) => Matcher::Regex(
                regex::bytes::RegexBuilder::new(&regex::escape(&self.pattern))
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| e.to_string())?,
            ),
            (PatternKind::Regex, ci) => Matcher::Regex(
                regex::bytes::RegexBuilder::new(&self.pattern)
                    .case_insensitive(ci)
                    .build()
                    .map_err(|e| e.to_string())?,
            ),
            (PatternKind::Exact, false) => Matcher::Exact {
                needle: self.pattern.as_bytes().to_vec(),
                finder: (!self.pattern.is_empty())
                    .then(|| Box::new(memmem::Finder::new(self.pattern.as_bytes()).into_owned())),
            },
            (PatternKind::Exact, true) => Matcher::Regex(
                regex::bytes::RegexBuilder::new(&format!("^{}$", regex::escape(&self.pattern)))
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| e.to_string())?,
            ),
        };
        // Slice-level scanning is only a valid shortcut when "some field
        // matches" implies "the raw bytes match somewhere":
        // - anchors refer to the haystack, so an anchored regex must see one
        //   record (or field) at a time;
        // - a column-restricted regex must see the unescaped field;
        // - a literal containing the quote byte can straddle a `""` escape;
        // - an exact match is verified per record anyway (a hit is only a
        //   candidate), and without a column every field must be split.
        let quote = dialect
            .quote
            .is_some_and(|q| self.pattern.as_bytes().contains(&q));
        let per_record = match self.kind {
            PatternKind::Regex => self.columns.is_some() || has_anchor(&self.pattern),
            PatternKind::Literal => self.columns.is_some() && quote,
            PatternKind::Exact => {
                self.columns.is_none() || quote || self.pattern.is_empty() || self.case_insensitive
            }
        };
        Ok(Compiled {
            matcher,
            columns: self.columns.clone(),
            any_field: self.kind == PatternKind::Exact && self.columns.is_none(),
            invert: self.invert,
            per_record,
            dialect,
        })
    }
}

fn has_anchor(pattern: &str) -> bool {
    pattern.contains('^')
        || pattern.contains('$')
        || pattern.contains("\\A")
        || pattern.contains("\\z")
}

enum Matcher {
    Literal(Box<memmem::Finder<'static>>),
    Regex(regex::bytes::Regex),
    /// Whole-field equality; `finder` locates candidates in raw slices.
    Exact {
        needle: Vec<u8>,
        finder: Option<Box<memmem::Finder<'static>>>,
    },
}

impl Matcher {
    /// First match starting at or after `from`, as `(start, end)`. For
    /// `Exact` this is a candidate that still needs [`Matcher::is_match`]
    /// on the field.
    #[inline]
    fn find(&self, hay: &[u8], from: usize) -> Option<(usize, usize)> {
        match self {
            Matcher::Literal(f) => f
                .find(&hay[from..])
                .map(|p| (from + p, from + p + f.needle().len())),
            Matcher::Regex(r) => r.find_at(hay, from).map(|m| (m.start(), m.end())),
            Matcher::Exact {
                finder: Some(f), ..
            } => f
                .find(&hay[from..])
                .map(|p| (from + p, from + p + f.needle().len())),
            Matcher::Exact { finder: None, .. } => None,
        }
    }

    #[inline]
    fn is_match(&self, hay: &[u8]) -> bool {
        match self {
            Matcher::Literal(f) => f.find(hay).is_some(),
            Matcher::Regex(r) => r.is_match(hay),
            Matcher::Exact { needle, .. } => hay == needle.as_slice(),
        }
    }
}

/// A compiled [`SearchQuery`].
pub struct Compiled {
    matcher: Matcher,
    columns: Option<Vec<usize>>,
    /// Exact match against every field (no column given).
    any_field: bool,
    invert: bool,
    per_record: bool,
    dialect: Dialect,
}

impl Compiled {
    /// Does one record (its raw content bytes) satisfy the query? `invert`
    /// is *not* applied here.
    pub fn record_matches<'a>(&self, raw: &'a [u8], fields: &mut Vec<Cow<'a, [u8]>>) -> bool {
        match &self.columns {
            None if self.any_field => {
                split_fields(raw, self.dialect.delimiter, self.dialect.quote, fields);
                fields.iter().any(|f| self.matcher.is_match(f))
            }
            None => self.matcher.is_match(raw),
            Some(cols) => {
                split_fields(raw, self.dialect.delimiter, self.dialect.quote, fields);
                cols.iter()
                    .any(|&c| fields.get(c).is_some_and(|f| self.matcher.is_match(f)))
            }
        }
    }

    pub fn invert(&self) -> bool {
        self.invert
    }
}

/// Compressed set of matching record ordinals with rank/select.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MatchSet {
    bits: RoaringTreemap,
}

impl MatchSet {
    pub fn len(&self) -> u64 {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn contains(&self, record: u64) -> bool {
        self.bits.contains(record)
    }

    pub fn insert(&mut self, record: u64) {
        self.bits.insert(record);
    }

    /// The k-th smallest matching record (0-based).
    pub fn select(&self, k: u64) -> Option<u64> {
        self.bits.select(k)
    }

    /// Number of matching records `<= record`.
    pub fn rank(&self, record: u64) -> u64 {
        self.bits.rank(record)
    }

    /// Smallest match strictly after `record`.
    pub fn next_after(&self, record: u64) -> Option<u64> {
        self.bits.select(self.bits.rank(record))
    }

    /// Largest match strictly before `record`.
    pub fn prev_before(&self, record: u64) -> Option<u64> {
        let n = self.bits.rank(record.checked_sub(1)?);
        self.bits.select(n.checked_sub(1)?)
    }

    pub fn first(&self) -> Option<u64> {
        self.bits.min()
    }

    pub fn last(&self) -> Option<u64> {
        self.bits.max()
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.bits.iter()
    }

    /// Keep only the records also present in `other` (nested selections).
    pub fn intersect_with(&mut self, other: &MatchSet) {
        self.bits &= &other.bits;
    }

    pub(crate) fn union_with(&mut self, other: &RoaringTreemap) {
        self.bits |= other;
    }
}

/// Live state of a running search, shared between workers and observers.
pub struct SearchShared {
    pub matches: Mutex<MatchSet>,
    pub bytes: AtomicU64,
    pub records: AtomicU64,
    pub total: u64,
}

impl SearchShared {
    pub fn new(total: u64) -> SearchShared {
        SearchShared {
            matches: Mutex::new(MatchSet::default()),
            bytes: AtomicU64::new(0),
            records: AtomicU64::new(0),
            total,
        }
    }

    pub fn fraction(&self) -> f32 {
        if self.total == 0 {
            1.0
        } else {
            self.bytes.load(Ordering::Relaxed) as f32 / self.total as f32
        }
    }

    pub fn match_count(&self) -> u64 {
        self.matches.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SearchOptions<'a> {
    /// Worker threads; 0 = available parallelism.
    pub threads: usize,
    /// Target bytes per independent range (cut at checkpoints).
    pub range_bytes: u64,
    /// Bytes per matcher slice inside a range.
    pub slice_bytes: usize,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for SearchOptions<'_> {
    fn default() -> Self {
        SearchOptions {
            threads: 0,
            range_bytes: 64 << 20,
            slice_bytes: 4 << 20,
            cancel: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SearchOutcome {
    /// The whole file was scanned (not cancelled, no read error).
    pub complete: bool,
    pub records_scanned: u64,
    pub bytes_scanned: u64,
    pub elapsed: Duration,
    pub ranges: usize,
    pub threads: usize,
    /// First read error encountered, if any.
    pub error: Option<String>,
}

/// A byte range of the file starting at a known record boundary.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Range {
    pub(crate) start: u64,
    pub(crate) record: u64,
    pub(crate) end: u64,
}

/// Cut the file at checkpoints into ranges of roughly `range_bytes`. The
/// last range runs to EOF, which also covers whatever the index has not
/// reached yet.
pub(crate) fn plan_ranges(index: &SparseIndex, file_len: u64, range_bytes: u64) -> Vec<Range> {
    let cps = &index.checkpoints;
    let Some(&first) = cps.first() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut start = first;
    for cp in &cps[1..] {
        if cp.offset - start.offset >= range_bytes.max(1) {
            out.push(Range {
                start: start.offset,
                record: start.record,
                end: cp.offset,
            });
            start = *cp;
        }
    }
    out.push(Range {
        start: start.offset,
        record: start.record,
        end: file_len.max(start.offset),
    });
    out
}

/// Run a search. Matches and progress land in `shared` as the scan goes, so
/// a UI can show partial results; the outcome says whether the scan finished
/// or was cancelled.
pub fn search(
    source: &Source,
    index: &SparseIndex,
    query: &Compiled,
    opts: SearchOptions<'_>,
    shared: &SearchShared,
) -> SearchOutcome {
    let started = Instant::now();
    let ranges = plan_ranges(index, source.len(), opts.range_bytes);
    let threads = if opts.threads == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        opts.threads
    }
    .clamp(1, 64)
    .min(ranges.len().max(1));
    let cfg = index.params.dialect.scan_config(false);
    let next = AtomicUsize::new(0);
    let complete = AtomicBool::new(true);
    let error = Mutex::new(None);

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                crate::sys::boost_current_thread();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(range) = ranges.get(i) else { break };
                    if !search_range(source, query, cfg, *range, &opts, shared, &error) {
                        complete.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            });
        }
    });

    SearchOutcome {
        complete: complete.load(Ordering::Relaxed),
        records_scanned: shared.records.load(Ordering::Relaxed),
        bytes_scanned: shared.bytes.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        ranges: ranges.len(),
        threads,
        error: error.into_inner().ok().flatten().map(|e| e.to_string()),
    }
}

/// Scan one range slice by slice. Slices are read with positioned reads into
/// a thread-local buffer (sequential I/O with read-ahead, bounded RSS); only
/// records that straddle a slice boundary are fetched through the mapping.
/// Returns `false` if cancelled or on a read error.
fn search_range(
    source: &Source,
    query: &Compiled,
    cfg: ScanConfig,
    range: Range,
    opts: &SearchOptions<'_>,
    shared: &SearchShared,
    error: &Mutex<Option<std::io::Error>>,
) -> bool {
    let end = range.end.min(source.len());
    let mut pos = range.start.min(end);
    let mut scanner = Scanner::at(cfg, pos, range.record);
    let mut spans: Vec<RecordSpan> = Vec::new();
    let mut matched: Vec<bool> = Vec::new();
    let mut local = RoaringTreemap::new();
    let slice_bytes = opts.slice_bytes.max(64 << 10);
    let mut buf = vec![0u8; slice_bytes];

    while pos < end {
        if opts.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return false;
        }
        let want = ((end - pos) as usize).min(slice_bytes);
        let n = match source.read_at(&mut buf[..want], pos) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                if let Ok(mut slot) = error.lock() {
                    slot.get_or_insert(e);
                }
                return false;
            }
        };
        let e = pos + n as u64;
        spans.clear();
        let mut sink = |sp: RecordSpan| {
            spans.push(sp);
            Control::Continue
        };
        scanner.feed(&buf[..n], &mut sink);
        if e == end {
            scanner.finish(&mut sink);
        }
        evaluate_slice(query, source, &buf[..n], pos, &spans, &mut matched);
        local.clear();
        for (sp, &m) in spans.iter().zip(&matched) {
            if m != query.invert {
                local.insert(sp.ordinal);
            }
        }
        if !local.is_empty()
            && let Ok(mut m) = shared.matches.lock()
        {
            m.union_with(&local);
        }
        shared.bytes.fetch_add(n as u64, Ordering::Relaxed);
        shared
            .records
            .fetch_add(spans.len() as u64, Ordering::Relaxed);
        pos = e;
    }
    true
}

/// Decide, for every record that ended in the slice `buf` (which holds the
/// source bytes starting at absolute offset `s`), whether it matches.
fn evaluate_slice(
    q: &Compiled,
    source: &Source,
    buf: &[u8],
    s: u64,
    spans: &[RecordSpan],
    matched: &mut Vec<bool>,
) {
    matched.clear();
    matched.resize(spans.len(), false);
    let mut fields: Vec<Cow<[u8]>> = Vec::new();
    // A record inside the slice is read from the buffer; one that started in
    // an earlier slice comes from the mapping (its pages were just read).
    let record_bytes = |sp: &RecordSpan| -> &[u8] {
        if sp.start >= s {
            &buf[(sp.start - s) as usize..(sp.end - s) as usize]
        } else {
            source.slice(sp.start, sp.end)
        }
    };

    if q.per_record {
        for (i, sp) in spans.iter().enumerate() {
            matched[i] = q.record_matches(record_bytes(sp), &mut fields);
        }
        return;
    }

    let slice = buf;
    let s = s as usize;
    let mut i = 0;
    // Records that began before this slice: evaluate on their own bytes.
    while i < spans.len() && (spans[i].start as usize) < s {
        matched[i] = q.record_matches(record_bytes(&spans[i]), &mut fields);
        i += 1;
    }
    // Records fully inside the slice: one linear pass of the matcher, each
    // hit attributed to the record it starts in.
    let mut pending: Option<(usize, usize)> = None;
    let mut from = 0usize;
    while i < spans.len() {
        let rs = spans[i].start as usize - s;
        let re = spans[i].end as usize - s;
        let hit = match pending.take() {
            Some(h) => Some(h),
            None => q.matcher.find(slice, from.max(rs)),
        };
        let Some((hs, he)) = hit else {
            break; // no further hits anywhere in this slice
        };
        if hs < rs {
            // inside a terminator / skipped empty line: not part of any record
            from = rs;
            continue;
        }
        if hs >= re {
            // belongs to a later record, or to the trailing partial record
            // that will be re-evaluated when it completes in the next slice
            pending = Some((hs, he));
            i += 1;
            continue;
        }
        matched[i] = if he > re || q.columns.is_some() {
            q.record_matches(&slice[rs..re], &mut fields)
        } else {
            true
        };
        from = re;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use crate::synth::{Generator, Profile, Target};
    use std::io::Write as _;
    use std::sync::atomic::AtomicUsize as Counter;

    fn temp(data: &[u8]) -> std::path::PathBuf {
        static N: Counter = Counter::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gridsift-search-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    fn fixture(data: &[u8], stride: u32) -> (Source, SparseIndex) {
        let p = temp(data);
        let src = Source::open(&p).unwrap();
        let params = IndexParams {
            stride_records: stride,
            stride_bytes: u64::MAX,
            ..IndexParams::default()
        };
        let idx = build_index(&src, params, BuildOptions::default(), &mut |_, _| {}).unwrap();
        (src, idx)
    }

    fn run(
        src: &Source,
        idx: &SparseIndex,
        q: &SearchQuery,
        opts: SearchOptions<'_>,
    ) -> (Vec<u64>, SearchOutcome) {
        let c = q.compile(idx.params.dialect).unwrap();
        let shared = SearchShared::new(src.len());
        let out = search(src, idx, &c, opts, &shared);
        let m = shared.matches.lock().unwrap();
        (m.iter().collect(), out)
    }

    /// Ground truth: split every record and apply the query naively.
    fn reference(src: &Source, idx: &SparseIndex, q: &SearchQuery) -> Vec<u64> {
        let c = q.compile(idx.params.dialect).unwrap();
        let recs = crate::reader::locate_records(src, idx, 0, usize::MAX);
        let mut fields = Vec::new();
        recs.iter()
            .filter(|r| c.record_matches(r.raw(src), &mut fields) != q.invert)
            .map(|r| r.record)
            .collect()
    }

    #[test]
    fn literal_whole_record() {
        let data = b"id,text\n0,alpha\n1,beta\n2,\"gam\nma\"\n3,delta\n4,alphabet\n";
        let (src, idx) = fixture(data, 2);
        let (m, out) = run(
            &src,
            &idx,
            &SearchQuery::literal("alpha"),
            SearchOptions::default(),
        );
        assert_eq!(m, vec![0, 4]);
        assert!(out.complete);
        assert_eq!(out.records_scanned, 5);
        let (m, _) = run(
            &src,
            &idx,
            &SearchQuery::literal("gam\nma"),
            SearchOptions::default(),
        );
        assert_eq!(m, vec![2]);
        let (m, _) = run(
            &src,
            &idx,
            &SearchQuery::literal("zzz"),
            SearchOptions::default(),
        );
        assert!(m.is_empty());
    }

    #[test]
    fn invert_and_columns() {
        let data = b"a,b\nx,alpha\nalpha,y\nz,w\n";
        let (src, idx) = fixture(data, 1);
        let q = SearchQuery {
            columns: Some(vec![1]),
            ..SearchQuery::literal("alpha")
        };
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![0]);
        let q = SearchQuery {
            invert: true,
            ..SearchQuery::literal("alpha")
        };
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![2]);
        // column search sees unescaped field bytes
        let data = b"a,b\n\"say \"\"hi\"\"\",1\n";
        let (src, idx) = fixture(data, 1);
        let q = SearchQuery {
            columns: Some(vec![0]),
            ..SearchQuery::literal("say \"hi\"")
        };
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![0]);
    }

    #[test]
    fn regex_and_case() {
        let data = b"id,host\n0,cdn.example.com\n1,EXAMPLE.org\n2,foo.net\n3,example.co.jp\n";
        let (src, idx) = fixture(data, 2);
        let q = SearchQuery::regex(r"example\.(com|org)");
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![0]);
        let q = SearchQuery {
            case_insensitive: true,
            ..SearchQuery::regex(r"example\.(com|org)")
        };
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![0, 1]);
        let q = SearchQuery {
            case_insensitive: true,
            ..SearchQuery::literal("EXAMPLE")
        };
        assert_eq!(
            run(&src, &idx, &q, SearchOptions::default()).0,
            vec![0, 1, 3]
        );
        // anchored regex against a column is evaluated per field
        let q = SearchQuery {
            columns: Some(vec![1]),
            ..SearchQuery::regex(r"^example")
        };
        assert_eq!(run(&src, &idx, &q, SearchOptions::default()).0, vec![3]);
        assert!(SearchQuery::regex("(").compile(Dialect::default()).is_err());
    }

    #[test]
    fn slices_ranges_and_threads_agree_with_reference() {
        // enough rows for several ranges and many slice boundaries
        let mut data = Vec::new();
        Generator::new(Profile::Quotes, 3)
            .generate(&mut data, Target::Rows(20_000), None)
            .unwrap();
        let (src, idx) = fixture(&data, 97);
        let queries = [
            SearchQuery::literal("comma"),
            SearchQuery::literal("line two"),
            SearchQuery::literal("\"\""),
            SearchQuery::regex(r"a{3,}"),
            SearchQuery::regex(r"(?m)^\d+,plain"),
            SearchQuery {
                invert: true,
                ..SearchQuery::literal("note")
            },
            SearchQuery {
                columns: Some(vec![1]),
                ..SearchQuery::literal("quote")
            },
            SearchQuery {
                columns: Some(vec![2]),
                ..SearchQuery::regex(r"^note$")
            },
        ];
        for q in &queries {
            let want = reference(&src, &idx, q);
            assert!(!want.is_empty(), "query {q:?} should match something");
            for (threads, range_bytes, slice_bytes) in [
                (1, u64::MAX, 64 << 10),
                (4, 100_000, 64 << 10),
                (3, 50_000, 64 << 10),
            ] {
                let opts = SearchOptions {
                    threads,
                    range_bytes,
                    slice_bytes,
                    cancel: None,
                };
                let (got, out) = run(&src, &idx, q, opts);
                assert_eq!(
                    got, want,
                    "query {q:?} threads={threads} range={range_bytes}"
                );
                assert!(out.complete);
                assert_eq!(out.records_scanned, 20_000);
            }
        }
    }

    #[test]
    fn cancel_stops_early() {
        let mut data = Vec::new();
        Generator::new(Profile::Narrow, 1)
            .generate(&mut data, Target::Rows(5_000), None)
            .unwrap();
        let (src, idx) = fixture(&data, 100);
        let cancel = AtomicBool::new(true);
        let opts = SearchOptions {
            cancel: Some(&cancel),
            ..SearchOptions::default()
        };
        let (_, out) = run(&src, &idx, &SearchQuery::literal("tcp"), opts);
        assert!(!out.complete);
    }

    #[test]
    fn matchset_navigation() {
        let mut m = MatchSet::default();
        for r in [3u64, 10, 11, 500_000_000_000] {
            m.insert(r);
        }
        assert_eq!(m.len(), 4);
        assert_eq!(m.select(0), Some(3));
        assert_eq!(m.select(3), Some(500_000_000_000));
        assert_eq!(m.select(4), None);
        assert_eq!(m.rank(3), 1);
        assert_eq!(m.rank(2), 0);
        assert_eq!(m.rank(10), 2);
        assert_eq!(m.next_after(0), Some(3));
        assert_eq!(m.next_after(3), Some(10));
        assert_eq!(m.next_after(11), Some(500_000_000_000));
        assert_eq!(m.next_after(500_000_000_000), None);
        assert_eq!(m.prev_before(0), None);
        assert_eq!(m.prev_before(3), None);
        assert_eq!(m.prev_before(4), Some(3));
        assert_eq!(m.prev_before(11), Some(10));
        assert_eq!(m.prev_before(u64::MAX), Some(500_000_000_000));
        assert_eq!((m.first(), m.last()), (Some(3), Some(500_000_000_000)));
    }

    #[test]
    fn exact_matches_whole_fields_only() {
        // 10.0.0.1 must not select 10.0.0.10 / 10.0.0.100; embedded quotes
        // and empty values are fields like any other.
        let data = b"ip,host\n10.0.0.1,a\n10.0.0.10,b\n10.0.0.100,c\n\"10.0.0.1\",d\n,e\n\"say \"\"hi\"\"\",f\n";
        let (src, idx) = fixture(data, 2);
        let cases: Vec<(SearchQuery, Vec<u64>)> = vec![
            (SearchQuery::exact("10.0.0.1", Some(0)), vec![0, 3]),
            (SearchQuery::exact("10.0.0.1", None), vec![0, 3]),
            (SearchQuery::literal("10.0.0.1"), vec![0, 1, 2, 3]),
            (SearchQuery::exact("", Some(0)), vec![4]),
            (SearchQuery::exact("say \"hi\"", Some(0)), vec![5]),
            (SearchQuery::exact("b", None), vec![1]),
            (
                SearchQuery {
                    case_insensitive: true,
                    ..SearchQuery::exact("B", Some(1))
                },
                vec![1],
            ),
            (
                SearchQuery {
                    invert: true,
                    ..SearchQuery::exact("10.0.0.1", Some(0))
                },
                vec![1, 2, 4, 5],
            ),
        ];
        for (q, want) in cases {
            for threads in [1, 3] {
                let (m, out) = run(
                    &src,
                    &idx,
                    &q,
                    SearchOptions {
                        threads,
                        range_bytes: 16,
                        ..SearchOptions::default()
                    },
                );
                assert!(out.complete);
                assert_eq!(m, want, "{q:?} with {threads} threads");
                assert_eq!(m, reference(&src, &idx, &q), "{q:?} vs reference");
            }
        }
        // the manifest spelling
        assert_eq!(
            serde_json::to_string(&PatternKind::Exact).unwrap(),
            "\"exact\""
        );
    }

    #[test]
    fn empty_and_header_only() {
        let (src, idx) = fixture(b"a,b\n", 1);
        let (m, out) = run(
            &src,
            &idx,
            &SearchQuery::literal("a"),
            SearchOptions::default(),
        );
        assert!(m.is_empty());
        assert!(out.complete);
        assert_eq!(out.ranges, 0);
    }
}
