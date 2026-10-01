//! Value frequencies (top-N) for one column, over all records or a selection.
//!
//! Workers scan index-cut ranges in parallel and count the column's values.
//! Each worker counts exactly until `exact_cap` distinct values have been
//! seen, then switches to lossy counting (Manku & Motwani) so memory stays
//! bounded on high-cardinality columns. The result says whether it is exact
//! and carries an error bound otherwise; distinct values are counted exactly
//! when possible and estimated with HyperLogLog when not.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::enrich::Enrichment;
use crate::export::Selection;
use crate::index::{Checkpoint, SparseIndex};
use crate::reader::{StreamRange, stream_records_range};
use crate::record::nth_field;
use crate::scan::Control;
use crate::search::plan_ranges;
use crate::source::Source;

#[derive(Clone, Copy, Debug)]
pub struct FrequencyOptions<'a> {
    /// 0-based column.
    pub column: usize,
    /// Entries to return.
    pub top: usize,
    /// Distinct values a worker counts exactly before going lossy.
    pub exact_cap: usize,
    /// Lossy counting bucket width (1/ε): counts are under by at most
    /// records/width per worker once lossy.
    pub lossy_width: u64,
    /// Worker threads; 0 = available parallelism.
    pub threads: usize,
    pub range_bytes: u64,
    pub chunk_size: usize,
    /// Lets `column` address a derived column: indexes at or past the
    /// source width (`index.stats.expected_fields`) refer to
    /// [`Enrichment::derived_names`] in order.
    pub enrichment: Option<&'a Enrichment>,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for FrequencyOptions<'_> {
    fn default() -> Self {
        FrequencyOptions {
            column: 0,
            top: 50,
            exact_cap: 131_072,
            lossy_width: 10_000,
            threads: 0,
            range_bytes: 64 << 20,
            chunk_size: 4 << 20,
            enrichment: None,
            cancel: None,
        }
    }
}

/// Live progress of a running count.
pub struct FrequencyShared {
    pub bytes: AtomicU64,
    pub records: AtomicU64,
    pub total: u64,
}

impl FrequencyShared {
    pub fn new(total: u64) -> FrequencyShared {
        FrequencyShared {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrequencyEntry {
    /// The field bytes exactly as stored (unquoted).
    pub value: Vec<u8>,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrequencyResult {
    pub column: usize,
    /// Records in the selection that were examined.
    pub counted: u64,
    /// Records whose field was empty or missing.
    pub empty: u64,
    /// Distinct non-empty values: exact when `exact`, else an estimate.
    pub distinct: u64,
    pub exact: bool,
    /// Upper bound on how much any reported count may be under the truth.
    pub error_bound: u64,
    /// Most frequent values, descending (ties by value).
    pub top: Vec<FrequencyEntry>,
    pub complete: bool,
    pub elapsed: Duration,
    pub threads: usize,
}

struct Entry {
    count: u64,
    /// Lossy-counting error term: the count may be under by up to this.
    delta: u64,
}

struct Counter {
    cap: usize,
    width: u64,
    map: HashMap<Vec<u8>, Entry>,
    lossy: bool,
    counted: u64,
    empty: u64,
    next_prune: u64,
    hll: Hll,
}

impl Counter {
    fn new(cap: usize, width: u64) -> Counter {
        Counter {
            cap: cap.max(1),
            width: width.max(1),
            map: HashMap::new(),
            lossy: false,
            counted: 0,
            empty: 0,
            next_prune: 0,
            hll: Hll::new(),
        }
    }

    #[inline]
    fn add(&mut self, v: &[u8]) {
        self.counted += 1;
        if v.is_empty() {
            self.empty += 1;
            return;
        }
        self.hll.add(v);
        let bucket = self.counted / self.width;
        match self.map.get_mut(v) {
            Some(e) => e.count += 1,
            None => {
                if !self.lossy && self.map.len() >= self.cap {
                    self.lossy = true;
                    self.next_prune = (bucket + 1) * self.width;
                }
                let delta = if self.lossy { bucket } else { 0 };
                self.map.insert(v.to_vec(), Entry { count: 1, delta });
            }
        }
        if self.lossy && self.counted >= self.next_prune {
            let b = self.counted / self.width;
            self.map.retain(|_, e| e.count + e.delta > b);
            self.next_prune = (b + 1) * self.width;
        }
    }

    fn error_bound(&self) -> u64 {
        if self.lossy {
            self.counted / self.width
        } else {
            0
        }
    }
}

const HLL_P: u32 = 14;
const HLL_M: usize = 1 << HLL_P;

/// HyperLogLog distinct-count estimator (2^14 registers, ~0.8 % error).
struct Hll {
    regs: Vec<u8>,
}

impl Hll {
    fn new() -> Hll {
        Hll {
            regs: vec![0; HLL_M],
        }
    }

    #[inline]
    fn add(&mut self, v: &[u8]) {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        let x = h.finish();
        let idx = (x >> (64 - HLL_P)) as usize;
        let rank = ((x << HLL_P).leading_zeros() + 1).min(64 - HLL_P + 1) as u8;
        if rank > self.regs[idx] {
            self.regs[idx] = rank;
        }
    }

    fn merge(&mut self, other: &Hll) {
        for (a, b) in self.regs.iter_mut().zip(&other.regs) {
            *a = (*a).max(*b);
        }
    }

    fn estimate(&self) -> u64 {
        let m = HLL_M as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let z: f64 = self.regs.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let mut e = alpha * m * m / z;
        if e <= 2.5 * m {
            let zeros = self.regs.iter().filter(|&&r| r == 0).count();
            if zeros > 0 {
                e = m * (m / zeros as f64).ln();
            }
        }
        e.round() as u64
    }
}

/// Count the values of one column. Progress lands in `shared` as the scan
/// goes; the result says whether the scan finished.
pub fn frequency(
    source: &Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    opts: FrequencyOptions<'_>,
    shared: &FrequencyShared,
) -> io::Result<FrequencyResult> {
    let started = Instant::now();
    let ranges = plan_ranges(index, source.len(), opts.range_bytes);
    let threads = if opts.threads == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        opts.threads
    }
    .clamp(1, 64)
    .min(ranges.len().max(1));
    let dialect = index.params.dialect;
    let base = index.stats.expected_fields as usize;
    let enrichment = opts.enrichment;
    let next = AtomicUsize::new(0);
    let complete = AtomicBool::new(true);
    let counters: Mutex<Vec<Counter>> = Mutex::new(Vec::new());
    let error: Mutex<Option<io::Error>> = Mutex::new(None);

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                crate::sys::boost_current_thread();
                let mut c = Counter::new(opts.exact_cap, opts.lossy_width);
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(r) = ranges.get(i) else { break };
                    let before = c.counted;
                    let range = StreamRange {
                        from: Checkpoint {
                            record: r.record,
                            offset: r.start,
                        },
                        end: r.end,
                        chunk_size: opts.chunk_size,
                    };
                    let res = stream_records_range(
                        source,
                        index,
                        range,
                        opts.cancel,
                        &mut |b| {
                            shared.bytes.fetch_add(b, Ordering::Relaxed);
                        },
                        &mut |sp, bytes| {
                            if selection.includes(sp.ordinal) {
                                if opts.column >= base {
                                    match enrichment {
                                        Some(e) => c.add(&e.value(bytes, opts.column - base)),
                                        None => c.add(b""),
                                    }
                                } else {
                                    let v = nth_field(
                                        bytes,
                                        dialect.delimiter,
                                        dialect.quote,
                                        opts.column,
                                    );
                                    c.add(v.as_deref().unwrap_or(b""));
                                }
                            }
                            Control::Continue
                        },
                    );
                    shared
                        .records
                        .fetch_add(c.counted - before, Ordering::Relaxed);
                    match res {
                        Ok(true) => {}
                        Ok(false) => {
                            complete.store(false, Ordering::Relaxed);
                            break;
                        }
                        Err(e) => {
                            if let Ok(mut slot) = error.lock() {
                                slot.get_or_insert(e);
                            }
                            complete.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                if let Ok(mut all) = counters.lock() {
                    all.push(c);
                }
            });
        }
    });

    if let Some(e) = error.into_inner().ok().flatten() {
        return Err(e);
    }
    let counters = counters.into_inner().unwrap_or_default();
    let exact = counters.iter().all(|c| !c.lossy);
    let mut merged: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut hll = Hll::new();
    let (mut counted, mut empty, mut error_bound) = (0u64, 0u64, 0u64);
    for c in counters {
        counted += c.counted;
        empty += c.empty;
        error_bound += c.error_bound();
        hll.merge(&c.hll);
        for (k, e) in c.map {
            *merged.entry(k).or_insert(0) += e.count;
        }
    }
    let distinct = if exact {
        merged.len() as u64
    } else {
        hll.estimate()
    };
    let mut top: Vec<FrequencyEntry> = merged
        .into_iter()
        .map(|(value, count)| FrequencyEntry { value, count })
        .collect();
    top.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    top.truncate(opts.top);
    Ok(FrequencyResult {
        column: opts.column,
        counted,
        empty,
        distinct,
        exact,
        error_bound,
        top,
        complete: complete.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use crate::reader::locate_records;
    use crate::search::{SearchOptions, SearchQuery, SearchShared, search};
    use crate::synth::{Generator, Profile, Target};
    use std::sync::atomic::AtomicUsize as Counter2;

    fn fixture(profile: Profile, rows: u64, stride: u32) -> (Source, SparseIndex) {
        static N: Counter2 = Counter2::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gridsift-freq-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        let mut data = Vec::new();
        Generator::new(profile, 11)
            .generate(&mut data, Target::Rows(rows), None)
            .unwrap();
        std::fs::write(&p, &data).unwrap();
        let src = Source::open(&p).unwrap();
        let idx = build_index(
            &src,
            IndexParams {
                stride_records: stride,
                stride_bytes: u64::MAX,
                ..IndexParams::default()
            },
            BuildOptions::default(),
            &mut |_, _| {},
        )
        .unwrap();
        (src, idx)
    }

    /// Exact reference counts by splitting every record.
    fn reference(
        src: &Source,
        idx: &SparseIndex,
        column: usize,
        sel: &Selection<'_>,
    ) -> (HashMap<Vec<u8>, u64>, u64, u64) {
        let mut counts = HashMap::new();
        let (mut counted, mut empty) = (0u64, 0u64);
        let mut fields = Vec::new();
        for r in locate_records(src, idx, 0, usize::MAX) {
            if !sel.includes(r.record) {
                continue;
            }
            counted += 1;
            r.fields(src, idx, &mut fields);
            match fields.get(column).filter(|f| !f.is_empty()) {
                Some(f) => *counts.entry(f.to_vec()).or_insert(0) += 1,
                None => empty += 1,
            }
        }
        (counts, counted, empty)
    }

    fn run(
        src: &Source,
        idx: &SparseIndex,
        sel: Selection<'_>,
        opts: FrequencyOptions<'_>,
    ) -> FrequencyResult {
        let shared = FrequencyShared::new(src.len());
        let r = frequency(src, idx, sel, opts, &shared).unwrap();
        assert_eq!(shared.records.load(Ordering::Relaxed), r.counted);
        r
    }

    #[test]
    fn exact_counts_match_reference() {
        let (src, idx) = fixture(Profile::Narrow, 20_000, 97);
        for column in [4usize, 7, 5, 9, 12, 11] {
            let (want, counted, empty) = reference(&src, &idx, column, &Selection::All);
            for threads in [1, 3, 8] {
                let opts = FrequencyOptions {
                    column,
                    top: 1000,
                    threads,
                    range_bytes: 100_000,
                    chunk_size: 64 << 10,
                    ..FrequencyOptions::default()
                };
                let r = run(&src, &idx, Selection::All, opts);
                assert!(r.exact && r.complete, "column {column}");
                assert_eq!(r.error_bound, 0);
                assert_eq!((r.counted, r.empty), (counted, empty), "column {column}");
                assert_eq!(r.distinct as usize, want.len(), "column {column}");
                let got: HashMap<Vec<u8>, u64> =
                    r.top.iter().map(|e| (e.value.clone(), e.count)).collect();
                if want.len() <= 1000 {
                    assert_eq!(got, want, "column {column} threads {threads}");
                } else {
                    for e in &r.top {
                        assert_eq!(want[&e.value], e.count);
                    }
                }
                // descending order, ties by value
                for w in r.top.windows(2) {
                    assert!(
                        w[0].count > w[1].count
                            || (w[0].count == w[1].count && w[0].value < w[1].value)
                    );
                }
            }
        }
        // proto is heavily tcp
        let r = run(
            &src,
            &idx,
            Selection::All,
            FrequencyOptions {
                column: 4,
                ..FrequencyOptions::default()
            },
        );
        assert_eq!(r.top[0].value, b"tcp");
        assert!(r.top[0].count > r.counted * 8 / 10);
        assert_eq!(r.distinct, 2);
        // a column past the end is all empty
        let r = run(
            &src,
            &idx,
            Selection::All,
            FrequencyOptions {
                column: 40,
                ..FrequencyOptions::default()
            },
        );
        assert_eq!(r.empty, r.counted);
        assert!(r.top.is_empty());
        assert_eq!(r.distinct, 0);
    }

    #[test]
    fn selections_restrict_the_count() {
        let (src, idx) = fixture(Profile::Narrow, 20_000, 128);
        let q = SearchQuery::literal("deny");
        let c = q.compile(idx.params.dialect).unwrap();
        let shared = SearchShared::new(src.len());
        search(&src, &idx, &c, SearchOptions::default(), &shared);
        let m = shared.matches.lock().unwrap();
        let sel = Selection::Matches(&m);
        let (want, counted, _) = reference(&src, &idx, 10, &sel);
        let r = run(
            &src,
            &idx,
            sel,
            FrequencyOptions {
                column: 10,
                ..FrequencyOptions::default()
            },
        );
        assert_eq!(r.counted, counted);
        assert_eq!(r.counted, m.len());
        assert_eq!(r.top.len(), 1);
        assert_eq!(r.top[0].value, b"deny");
        assert_eq!(r.top[0].count, want[b"deny".as_slice()]);

        let sel = Selection::Range {
            first: 19_990,
            count: 100,
        };
        let r = run(
            &src,
            &idx,
            sel,
            FrequencyOptions {
                column: 0,
                ..FrequencyOptions::default()
            },
        );
        assert_eq!(r.counted, 10);
    }

    #[test]
    fn lossy_mode_keeps_heavy_hitters_and_bounds() {
        // dst_port: ~60 % 443, ~20 % 80, ~10 % 8080, the rest random; force a
        // tiny exact cap so every worker goes lossy
        let (src, idx) = fixture(Profile::Narrow, 20_000, 64);
        let (want, _, _) = reference(&src, &idx, 3, &Selection::All);
        let opts = FrequencyOptions {
            column: 3,
            top: 20,
            exact_cap: 8,
            lossy_width: 200,
            threads: 4,
            range_bytes: 200_000,
            chunk_size: 64 << 10,
            ..FrequencyOptions::default()
        };
        let r = run(&src, &idx, Selection::All, opts);
        assert!(!r.exact);
        assert!(r.error_bound > 0);
        // every reported count is a lower bound within the error bound
        for e in &r.top {
            let truth = want[&e.value];
            assert!(e.count <= truth, "{:?}", String::from_utf8_lossy(&e.value));
            assert!(
                truth - e.count <= r.error_bound,
                "{:?}: {} vs {} (bound {})",
                String::from_utf8_lossy(&e.value),
                e.count,
                truth,
                r.error_bound
            );
        }
        // the heavy hitters are reported in the right order
        assert_eq!(r.top[0].value, b"443");
        assert_eq!(r.top[1].value, b"80");
        assert_eq!(r.top[2].value, b"8080");
        // distinct estimate within a few percent
        let truth = want.len() as f64;
        assert!(
            (r.distinct as f64 - truth).abs() / truth < 0.05,
            "{} vs {truth}",
            r.distinct
        );
    }

    #[test]
    fn hll_estimate_is_close() {
        let mut h = Hll::new();
        for i in 0..200_000u32 {
            h.add(format!("value-{i}").as_bytes());
        }
        let e = h.estimate() as f64;
        assert!((e - 200_000.0).abs() / 200_000.0 < 0.03, "{e}");
        let mut small = Hll::new();
        for i in 0..50u32 {
            small.add(&i.to_le_bytes());
        }
        assert!((45..=55).contains(&small.estimate()));
    }

    #[test]
    fn cancel_and_empty() {
        let (src, idx) = fixture(Profile::Narrow, 2_000, 64);
        let cancel = AtomicBool::new(true);
        let opts = FrequencyOptions {
            cancel: Some(&cancel),
            ..FrequencyOptions::default()
        };
        let r = run(&src, &idx, Selection::All, opts);
        assert!(!r.complete);
        let (src, idx) = fixture(Profile::Quotes, 0, 64);
        let r = run(&src, &idx, Selection::All, FrequencyOptions::default());
        assert!(r.complete && r.top.is_empty() && r.counted == 0);
    }
}
