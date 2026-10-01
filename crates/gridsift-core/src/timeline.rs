//! Time distribution of records: parse a timestamp column, count records per
//! time bucket in parallel, and turn a time range back into a selection.
//!
//! Parsing is hand-written for the formats the profiler recognises (ISO
//! 8601 / RFC 3339, `YYYY/MM/DD`, Apache CLF, syslog, US-style, Unix epoch)
//! and yields Unix seconds; naive timestamps are taken as UTC. Workers count
//! at one-second resolution and coarsen to minutes, hours or days when a
//! file spans too much time for the per-worker memory cap, so memory stays
//! bounded whatever the range.

use std::collections::HashMap;
use std::io;

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use roaring::RoaringTreemap;

use crate::export::Selection;
use crate::frequency::FrequencyShared;
use crate::index::{Checkpoint, SparseIndex};
use crate::reader::{StreamRange, stream_records_range};
use crate::record::nth_field;
use crate::scan::Control;
use crate::search::{SearchOutcome, SearchShared, plan_ranges};
use crate::source::Source;

// ---------------------------------------------------------------------------
// timestamp parsing

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn digits(v: &[u8], n: usize) -> Option<u32> {
    if v.len() < n || !v[..n].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(v[..n].iter().fold(0u32, |a, b| a * 10 + (b - b'0') as u32))
}

fn month_abbr(v: &[u8]) -> Option<u32> {
    if v.len() < 3 {
        return None;
    }
    Some(match &v[..3].to_ascii_lowercase()[..] {
        b"jan" => 1,
        b"feb" => 2,
        b"mar" => 3,
        b"apr" => 4,
        b"may" => 5,
        b"jun" => 6,
        b"jul" => 7,
        b"aug" => 8,
        b"sep" => 9,
        b"oct" => 10,
        b"nov" => 11,
        b"dec" => 12,
        _ => return None,
    })
}

fn valid_date(y: i64, m: u32, d: u32) -> bool {
    (1..=12).contains(&m) && (1..=31).contains(&d) && (1900..=2200).contains(&y)
}

/// `HH:MM[:SS[.frac]]` → seconds of day and the index after it.
fn time_of_day(v: &[u8]) -> Option<(i64, usize)> {
    let h = digits(v, 2)?;
    if v.get(2) != Some(&b':') {
        return None;
    }
    let m = digits(&v[3..], 2)?;
    let mut i = 5;
    let mut s = 0;
    if v.get(5) == Some(&b':') {
        s = digits(&v[6..], 2)?;
        i = 8;
        if matches!(v.get(i), Some(b'.') | Some(b',')) {
            i += 1;
            while v.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
    }
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some(((h * 3600 + m * 60 + s) as i64, i))
}

/// Zone suffix: `Z`, `±HH:MM`, `±HHMM`, `±HH`; returns the offset in seconds.
fn zone(v: &[u8]) -> Option<(i64, usize)> {
    match v.first() {
        None => Some((0, 0)),
        Some(b'Z') | Some(b'z') => Some((0, 1)),
        Some(&sign @ (b'+' | b'-')) => {
            let h = digits(&v[1..], 2)? as i64;
            let (m, n) = if v.get(3) == Some(&b':') {
                (digits(&v[4..], 2)? as i64, 6)
            } else if v.len() >= 5 && v[3..5].iter().all(u8::is_ascii_digit) {
                (digits(&v[3..], 2)? as i64, 5)
            } else {
                (0, 3)
            };
            let off = h * 3600 + m * 60;
            Some((if sign == b'-' { -off } else { off }, n))
        }
        _ => None,
    }
}

/// Parse a timestamp into Unix seconds. `reference_year` is used for
/// formats without a year (syslog).
pub fn parse_timestamp(v: &[u8], reference_year: i64) -> Option<i64> {
    let s = v.iter().position(|b| !b.is_ascii_whitespace())?;
    let e = v.iter().rposition(|b| !b.is_ascii_whitespace())? + 1;
    let v = &v[s..e];
    if v.is_empty() || v.len() > 40 {
        return None;
    }
    // Unix epoch: seconds (10 digits), milliseconds (13), microseconds (16)
    if v.iter().all(u8::is_ascii_digit) {
        return match v.len() {
            10 => std::str::from_utf8(v).ok()?.parse::<i64>().ok(),
            13 => std::str::from_utf8(v)
                .ok()?
                .parse::<i64>()
                .ok()
                .map(|ms| ms / 1000),
            16 => std::str::from_utf8(v)
                .ok()?
                .parse::<i64>()
                .ok()
                .map(|us| us / 1_000_000),
            _ => None,
        };
    }
    // ISO 8601: YYYY-MM-DD[T ]HH:MM[:SS[.f]][zone]  and  YYYY/MM/DD[ HH:MM[:SS]]
    if let Some(y) = digits(v, 4)
        && matches!(v.get(4), Some(b'-') | Some(b'/'))
    {
        let sep = v[4];
        let m = digits(&v[5..], 2)?;
        if v.get(7) != Some(&sep) {
            return None;
        }
        let d = digits(&v[8..], 2)?;
        if !valid_date(y as i64, m, d) {
            return None;
        }
        let day = days_from_civil(y as i64, m, d) * 86_400;
        let rest = &v[10..];
        if rest.is_empty() {
            return Some(day);
        }
        if !matches!(rest[0], b'T' | b't' | b' ') {
            return None;
        }
        let (tod, n) = time_of_day(&rest[1..])?;
        let (off, z) = zone(&rest[1 + n..])?;
        if rest.len() != 1 + n + z {
            return None;
        }
        return Some(day + tod - off);
    }
    // Apache CLF: DD/Mon/YYYY:HH:MM:SS [±HHMM]
    if v.len() >= 20 && v[2] == b'/' && v[6] == b'/' && v[11] == b':' {
        let d = digits(v, 2)?;
        let m = month_abbr(&v[3..6])?;
        let y = digits(&v[7..], 4)? as i64;
        if !valid_date(y, m, d) {
            return None;
        }
        let (tod, n) = time_of_day(&v[12..])?;
        let mut rest = &v[12 + n..];
        if rest.first() == Some(&b' ') {
            rest = &rest[1..];
        }
        let (off, z) = zone(rest)?;
        if rest.len() != z {
            return None;
        }
        return Some(days_from_civil(y, m, d) * 86_400 + tod - off);
    }
    // syslog: Mon DD HH:MM:SS (no year)
    if v.len() >= 15
        && v[3] == b' '
        && let Some(m) = month_abbr(v)
    {
        let mut i = 4;
        while v.get(i) == Some(&b' ') {
            i += 1;
        }
        let dlen = v[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        if (1..=2).contains(&dlen) {
            let d = digits(&v[i..], dlen)?;
            i += dlen;
            if v.get(i) == Some(&b' ') {
                let (tod, n) = time_of_day(&v[i + 1..])?;
                if v.len() == i + 1 + n && valid_date(reference_year, m, d) {
                    return Some(days_from_civil(reference_year, m, d) * 86_400 + tod);
                }
            }
        }
    }
    // US: M/D/YYYY[ h:mm[:ss][ AM|PM]]
    {
        let mlen = v.iter().take_while(|b| b.is_ascii_digit()).count();
        if (1..=2).contains(&mlen) && v.get(mlen) == Some(&b'/') {
            let m = digits(v, mlen)?;
            let rest = &v[mlen + 1..];
            let dlen = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            if (1..=2).contains(&dlen) && rest.get(dlen) == Some(&b'/') {
                let d = digits(rest, dlen)?;
                let rest = &rest[dlen + 1..];
                let y = digits(rest, 4)? as i64;
                if !valid_date(y, m, d) {
                    return None;
                }
                let day = days_from_civil(y, m, d) * 86_400;
                let rest = &rest[4..];
                if rest.is_empty() {
                    return Some(day);
                }
                if rest[0] != b' ' {
                    return None;
                }
                let rest = &rest[1..];
                // hours may be one digit here
                let hlen = rest.iter().take_while(|b| b.is_ascii_digit()).count();
                if !(1..=2).contains(&hlen) || rest.get(hlen) != Some(&b':') {
                    return None;
                }
                let mut h = digits(rest, hlen)? as i64;
                let (rest_tod, n) = time_of_day_from_minutes(&rest[hlen + 1..])?;
                let mut tail = &rest[hlen + 1 + n..];
                if tail.first() == Some(&b' ') {
                    tail = &tail[1..];
                }
                if tail.len() == 2 {
                    match &tail.to_ascii_uppercase()[..] {
                        b"AM" => {
                            if h == 12 {
                                h = 0;
                            }
                        }
                        b"PM" => {
                            if h < 12 {
                                h += 12;
                            }
                        }
                        _ => return None,
                    }
                } else if !tail.is_empty() {
                    return None;
                }
                if h > 23 {
                    return None;
                }
                return Some(day + h * 3600 + rest_tod);
            }
        }
    }
    None
}

/// `MM[:SS]` → seconds and the index after it.
fn time_of_day_from_minutes(v: &[u8]) -> Option<(i64, usize)> {
    let m = digits(v, 2)?;
    let mut i = 2;
    let mut s = 0;
    if v.get(2) == Some(&b':') {
        s = digits(&v[3..], 2)?;
        i = 5;
    }
    if m > 59 || s > 60 {
        return None;
    }
    Some(((m * 60 + s) as i64, i))
}

/// Current calendar year (UTC), for year-less formats.
pub fn current_year() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = (secs / 86_400) as i64;
    // reuse the civil conversion from synth
    let mut out = Vec::new();
    crate::synth::write_iso8601(&mut out, secs);
    std::str::from_utf8(&out[..4])
        .ok()
        .and_then(|y| y.parse().ok())
        .unwrap_or(1970 + days / 365)
}

// ---------------------------------------------------------------------------
// bucketed counting

#[derive(Clone, Copy, Debug)]
pub struct TimelineOptions<'a> {
    /// 0-based timestamp column (source columns only).
    pub column: usize,
    pub threads: usize,
    pub range_bytes: u64,
    pub chunk_size: usize,
    /// Year assumed for formats without one.
    pub reference_year: i64,
    /// Buckets a worker keeps before coarsening its resolution.
    pub max_entries: usize,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for TimelineOptions<'_> {
    fn default() -> Self {
        TimelineOptions {
            column: 0,
            threads: 0,
            range_bytes: 64 << 20,
            chunk_size: 4 << 20,
            reference_year: current_year(),
            max_entries: 500_000,
            cancel: None,
        }
    }
}

/// Coarsening steps in seconds: 1 s → 1 min → 1 h → 1 day.
const RESOLUTIONS: [i64; 4] = [1, 60, 3600, 86_400];

struct Buckets {
    resolution: i64,
    map: HashMap<i64, u64>,
    cap: usize,
    parsed: u64,
    unparsed: u64,
    min: Option<i64>,
    max: Option<i64>,
}

impl Buckets {
    fn new(cap: usize) -> Buckets {
        Buckets {
            resolution: 1,
            map: HashMap::new(),
            cap: cap.max(16),
            parsed: 0,
            unparsed: 0,
            min: None,
            max: None,
        }
    }

    #[inline]
    fn add(&mut self, ts: i64) {
        self.parsed += 1;
        self.min = Some(self.min.map_or(ts, |m| m.min(ts)));
        self.max = Some(self.max.map_or(ts, |m| m.max(ts)));
        *self.map.entry(ts.div_euclid(self.resolution)).or_insert(0) += 1;
        if self.map.len() > self.cap {
            self.coarsen_once();
        }
    }

    fn coarsen_once(&mut self) {
        let Some(next) = RESOLUTIONS.iter().find(|&&r| r > self.resolution) else {
            return;
        };
        self.rekey(*next);
    }

    fn rekey(&mut self, resolution: i64) {
        if resolution == self.resolution {
            return;
        }
        let factor = resolution / self.resolution;
        let mut m: HashMap<i64, u64> = HashMap::with_capacity(self.map.len() / factor as usize + 1);
        for (k, c) in self.map.drain() {
            *m.entry(k.div_euclid(factor)).or_insert(0) += c;
        }
        self.map = m;
        self.resolution = resolution;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineResult {
    pub column: usize,
    /// Year assumed for formats without one (part of a cached result's
    /// identity: the same bytes parse differently in another year).
    #[serde(default)]
    pub reference_year: i64,
    /// Records in the selection that were examined.
    pub counted: u64,
    pub parsed: u64,
    pub unparsed: u64,
    /// Seconds per bucket in `buckets`.
    pub resolution: i64,
    /// `(bucket start in Unix seconds, count)`, ascending.
    pub buckets: Vec<(i64, u64)>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub complete: bool,
    pub elapsed: Duration,
    pub threads: usize,
}

/// Display widths to choose from (seconds).
pub const NICE_WIDTHS: [i64; 16] = [
    1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 10_800, 21_600, 43_200, 86_400, 604_800, 2_592_000,
];

impl TimelineResult {
    /// Smallest nice width (≥ the base resolution) that yields at most
    /// `target` buckets over the observed range.
    pub fn auto_width(&self, target: usize) -> i64 {
        let (Some(min), Some(max)) = (self.min, self.max) else {
            return self.resolution;
        };
        let span = (max - min).max(1);
        NICE_WIDTHS
            .iter()
            .copied()
            .filter(|&w| w >= self.resolution && w % self.resolution == 0)
            .find(|&w| span / w < target as i64)
            .unwrap_or(NICE_WIDTHS[NICE_WIDTHS.len() - 1].max(self.resolution))
    }

    /// Re-bucket to `width` seconds (a multiple of the base resolution);
    /// empty buckets inside the range are included with count 0.
    pub fn rebucket(&self, width: i64) -> Vec<(i64, u64)> {
        let width = width.max(self.resolution);
        let mut m: HashMap<i64, u64> = HashMap::new();
        for &(start, c) in &self.buckets {
            *m.entry((start * self.resolution).div_euclid(width))
                .or_insert(0) += c;
        }
        let (Some(min), Some(max)) = (self.min, self.max) else {
            return Vec::new();
        };
        let first = min.div_euclid(width);
        let last = max.div_euclid(width);
        (first..=last)
            .map(|k| (k * width, m.get(&k).copied().unwrap_or(0)))
            .collect()
    }
}

/// Count records per time bucket over a selection.
pub fn timeline(
    source: &Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    opts: TimelineOptions<'_>,
    shared: &FrequencyShared,
) -> io::Result<TimelineResult> {
    let started = Instant::now();
    let ranges = plan_ranges(index, source.len(), opts.range_bytes);
    let threads = worker_count(opts.threads, ranges.len());
    let dialect = index.params.dialect;
    let next = AtomicUsize::new(0);
    let complete = AtomicBool::new(true);
    let workers: Mutex<Vec<Buckets>> = Mutex::new(Vec::new());
    let error: Mutex<Option<io::Error>> = Mutex::new(None);
    let counted = std::sync::atomic::AtomicU64::new(0);

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                crate::sys::boost_current_thread();
                let mut b = Buckets::new(opts.max_entries);
                let mut seen = 0u64;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(r) = ranges.get(i) else { break };
                    let range = StreamRange {
                        from: Checkpoint {
                            record: r.record,
                            offset: r.start,
                        },
                        end: r.end,
                        chunk_size: opts.chunk_size,
                    };
                    let before = seen;
                    let res = stream_records_range(
                        source,
                        index,
                        range,
                        opts.cancel,
                        &mut |n| {
                            shared.bytes.fetch_add(n, Ordering::Relaxed);
                        },
                        &mut |sp, bytes| {
                            if selection.includes(sp.ordinal) {
                                seen += 1;
                                let v =
                                    nth_field(bytes, dialect.delimiter, dialect.quote, opts.column);
                                match v
                                    .as_deref()
                                    .and_then(|v| parse_timestamp(v, opts.reference_year))
                                {
                                    Some(ts) => b.add(ts),
                                    None => b.unparsed += 1,
                                }
                            }
                            Control::Continue
                        },
                    );
                    shared.records.fetch_add(seen - before, Ordering::Relaxed);
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
                counted.fetch_add(seen, Ordering::Relaxed);
                if let Ok(mut all) = workers.lock() {
                    all.push(b);
                }
            });
        }
    });
    if let Some(e) = error.into_inner().ok().flatten() {
        return Err(e);
    }

    let mut workers = workers.into_inner().unwrap_or_default();
    let resolution = workers.iter().map(|b| b.resolution).max().unwrap_or(1);
    let mut merged: HashMap<i64, u64> = HashMap::new();
    let (mut parsed, mut unparsed) = (0u64, 0u64);
    let (mut min, mut max): (Option<i64>, Option<i64>) = (None, None);
    for b in workers.iter_mut() {
        b.rekey(resolution);
        parsed += b.parsed;
        unparsed += b.unparsed;
        min = match (min, b.min) {
            (Some(a), Some(c)) => Some(a.min(c)),
            (a, c) => a.or(c),
        };
        max = match (max, b.max) {
            (Some(a), Some(c)) => Some(a.max(c)),
            (a, c) => a.or(c),
        };
        for (k, c) in b.map.drain() {
            *merged.entry(k).or_insert(0) += c;
        }
    }
    let mut buckets: Vec<(i64, u64)> = merged.into_iter().collect();
    buckets.sort_unstable();
    Ok(TimelineResult {
        column: opts.column,
        reference_year: opts.reference_year,
        counted: counted.load(Ordering::Relaxed),
        parsed,
        unparsed,
        resolution,
        buckets,
        min,
        max,
        complete: complete.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        threads,
    })
}

fn worker_count(requested: usize, ranges: usize) -> usize {
    if requested == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        requested
    }
    .clamp(1, 64)
    .min(ranges.max(1))
}

/// Select the records whose timestamp falls in `from..to` (Unix seconds,
/// `to` exclusive), within `selection`. Matches land in `shared` like a
/// search's do.
pub fn select_time_range(
    source: &Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    from: i64,
    to: i64,
    opts: TimelineOptions<'_>,
    shared: &SearchShared,
) -> io::Result<SearchOutcome> {
    let started = Instant::now();
    let ranges = plan_ranges(index, source.len(), opts.range_bytes);
    let threads = worker_count(opts.threads, ranges.len());
    let dialect = index.params.dialect;
    let next = AtomicUsize::new(0);
    let complete = AtomicBool::new(true);
    let error: Mutex<Option<io::Error>> = Mutex::new(None);

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                crate::sys::boost_current_thread();
                let mut local = RoaringTreemap::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(r) = ranges.get(i) else { break };
                    let range = StreamRange {
                        from: Checkpoint {
                            record: r.record,
                            offset: r.start,
                        },
                        end: r.end,
                        chunk_size: opts.chunk_size,
                    };
                    local.clear();
                    let mut seen = 0u64;
                    let res = stream_records_range(
                        source,
                        index,
                        range,
                        opts.cancel,
                        &mut |n| {
                            shared.bytes.fetch_add(n, Ordering::Relaxed);
                        },
                        &mut |sp, bytes| {
                            if selection.includes(sp.ordinal) {
                                seen += 1;
                                let v =
                                    nth_field(bytes, dialect.delimiter, dialect.quote, opts.column);
                                if let Some(ts) = v
                                    .as_deref()
                                    .and_then(|v| parse_timestamp(v, opts.reference_year))
                                    && ts >= from
                                    && ts < to
                                {
                                    local.insert(sp.ordinal);
                                }
                            }
                            Control::Continue
                        },
                    );
                    shared.records.fetch_add(seen, Ordering::Relaxed);
                    if !local.is_empty()
                        && let Ok(mut m) = shared.matches.lock()
                    {
                        m.union_with(&local);
                    }
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
            });
        }
    });
    let err = error.into_inner().ok().flatten();
    Ok(SearchOutcome {
        complete: complete.load(Ordering::Relaxed) && err.is_none(),
        records_scanned: shared.records.load(Ordering::Relaxed),
        bytes_scanned: shared.bytes.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        ranges: ranges.len(),
        threads,
        error: err.map(|e| e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use crate::reader::locate_records;
    use crate::synth::{Generator, Profile, Target};
    use crate::sys::iso8601_utc;

    fn p(s: &str) -> Option<i64> {
        parse_timestamp(s.as_bytes(), 2026)
    }

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 9, 21), 20_717);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn parses_common_formats() {
        let t = 1_790_000_000; // 2026-09-21T14:13:20Z
        assert_eq!(p("2026-09-21T14:13:20Z"), Some(t));
        assert_eq!(p("2026-09-21 14:13:20"), Some(t));
        assert_eq!(p("2026-09-21T14:13:20.123456Z"), Some(t));
        assert_eq!(p("2026-09-21T23:13:20+09:00"), Some(t));
        assert_eq!(p("2026-09-21T23:13:20+0900"), Some(t));
        assert_eq!(p("2026-09-21T09:13:20-05:00"), Some(t));
        assert_eq!(p("2026-09-21T14:13"), Some(t - 20));
        assert_eq!(p("2026-09-21"), Some(t - 14 * 3600 - 13 * 60 - 20));
        assert_eq!(p("2026/09/21 14:13:20"), Some(t));
        assert_eq!(p("21/Sep/2026:14:13:20 +0000"), Some(t));
        assert_eq!(p("21/Sep/2026:23:13:20 +0900"), Some(t));
        assert_eq!(p("Sep 21 14:13:20"), Some(t));
        assert_eq!(
            p("Sep  1 00:00:00"),
            Some(days_from_civil(2026, 9, 1) * 86_400)
        );
        assert_eq!(p("9/21/2026 2:13:20 PM"), Some(t));
        assert_eq!(p("9/21/2026 12:13:20 AM"), Some(t - 14 * 3600));
        assert_eq!(p("09/21/2026"), Some(t - 14 * 3600 - 13 * 60 - 20));
        assert_eq!(p("1790000000"), Some(t));
        assert_eq!(p("1790000000123"), Some(t));
        assert_eq!(p("  1790000000  "), Some(t));
        for bad in [
            "",
            "2026-13-01",
            "2026-09-21T25:00:00Z",
            "yesterday",
            "12345",
            "2026-09-21T14:13:20Q",
            "Foo 21 14:13:20",
            "21/Sep/2026",
            "9/21/2026 2:13:20 XM",
        ] {
            assert_eq!(p(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn buckets_coarsen_under_the_cap() {
        let mut b = Buckets::new(16);
        for ts in 0..1000i64 {
            b.add(ts * 7); // sparse seconds
        }
        assert!(b.resolution >= 60);
        assert_eq!(b.map.values().sum::<u64>(), 1000);
        assert_eq!(b.parsed, 1000);
        assert_eq!((b.min, b.max), (Some(0), Some(999 * 7)));
    }

    fn fixture(rows: u64) -> (Source, SparseIndex) {
        let dir =
            std::env::temp_dir().join(format!("gridsift-timeline-{}-{rows}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.csv");
        let mut data = Vec::new();
        Generator::new(Profile::Narrow, 3)
            .generate(&mut data, Target::Rows(rows), None)
            .unwrap();
        std::fs::write(&p, &data).unwrap();
        let src = Source::open(&p).unwrap();
        let idx = build_index(
            &src,
            IndexParams {
                stride_records: 128,
                stride_bytes: u64::MAX,
                ..IndexParams::default()
            },
            BuildOptions::default(),
            &mut |_, _| {},
        )
        .unwrap();
        (src, idx)
    }

    #[test]
    fn timeline_matches_reference_and_range_selection() {
        let (src, idx) = fixture(20_000);
        // reference: parse every timestamp ourselves
        let recs = locate_records(&src, &idx, 0, usize::MAX);
        let mut fields = Vec::new();
        let mut want: HashMap<i64, u64> = HashMap::new();
        let mut all_ts = Vec::new();
        for r in &recs {
            r.fields(&src, &idx, &mut fields);
            let ts = parse_timestamp(&fields[0], 2026).unwrap();
            all_ts.push((r.record, ts));
            *want.entry(ts.div_euclid(60)).or_insert(0) += 1;
        }
        let opts = TimelineOptions {
            column: 0,
            threads: 4,
            range_bytes: 200_000,
            chunk_size: 64 << 10,
            ..TimelineOptions::default()
        };
        let shared = FrequencyShared::new(src.len());
        let t = timeline(&src, &idx, Selection::All, opts, &shared).unwrap();
        assert!(t.complete);
        assert_eq!(t.counted, 20_000);
        assert_eq!(t.parsed, 20_000);
        assert_eq!(t.unparsed, 0);
        assert_eq!(t.resolution, 1);
        assert_eq!(t.buckets.iter().map(|b| b.1).sum::<u64>(), 20_000);
        let minutes = t.rebucket(60);
        let got: HashMap<i64, u64> = minutes
            .iter()
            .filter(|b| b.1 > 0)
            .map(|&(s, c)| (s / 60, c))
            .collect();
        assert_eq!(got, want);
        // contiguous, ascending, zero-filled
        for w in minutes.windows(2) {
            assert_eq!(w[1].0 - w[0].0, 60);
        }
        let width = t.auto_width(200);
        assert!(t.rebucket(width).len() <= 200);
        // the generator starts at 2026-09-21T14:13:20Z and jitters 0..3 s per row
        let min = t.min.unwrap();
        assert!(
            (1_790_000_000..=1_790_000_002).contains(&min),
            "{}",
            iso8601_utc(min as u64)
        );

        // time-range selection agrees with the reference
        let from = t.min.unwrap() + 3600;
        let to = from + 1800;
        let expect: Vec<u64> = all_ts
            .iter()
            .filter(|(_, ts)| *ts >= from && *ts < to)
            .map(|(r, _)| *r)
            .collect();
        let ss = SearchShared::new(src.len());
        let out = select_time_range(&src, &idx, Selection::All, from, to, opts, &ss).unwrap();
        assert!(out.complete);
        let got: Vec<u64> = ss.matches.lock().unwrap().iter().collect();
        assert_eq!(got, expect);
        assert!(!got.is_empty());
        // …and nested inside an existing selection
        let m = ss.matches.lock().unwrap().clone();
        let ss2 = SearchShared::new(src.len());
        let out2 = select_time_range(
            &src,
            &idx,
            Selection::Matches(&m),
            from + 900,
            to,
            opts,
            &ss2,
        )
        .unwrap();
        assert!(out2.complete);
        let got2: Vec<u64> = ss2.matches.lock().unwrap().iter().collect();
        let expect2: Vec<u64> = all_ts
            .iter()
            .filter(|(_, ts)| *ts >= from + 900 && *ts < to)
            .map(|(r, _)| *r)
            .collect();
        assert_eq!(got2, expect2);
    }

    #[test]
    fn unparseable_column_counts_as_unparsed() {
        let (src, idx) = fixture(500);
        let opts = TimelineOptions {
            column: 5, // host
            ..TimelineOptions::default()
        };
        let shared = FrequencyShared::new(src.len());
        let t = timeline(&src, &idx, Selection::All, opts, &shared).unwrap();
        assert_eq!(t.unparsed, 500);
        assert_eq!(t.parsed, 0);
        assert!(t.buckets.is_empty());
        assert!(t.rebucket(60).is_empty());
    }
}
