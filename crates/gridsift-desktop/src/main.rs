//! gridsift desktop: an egui/eframe shell over `gridsift-core`.
//!
//! Open → rows are visible at once (bootstrap index) → the sparse index and
//! SHA-256 are built on a background thread while the grid stays usable →
//! searches run in parallel on worker threads and can be shown as highlights
//! or as a filtered view.
//!
//! The source is never written to; the only file this app creates is the
//! index sidecar in the user's cache directory.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, Key, Modifiers, RichText};
use egui_extras::{Column, TableBuilder};
use gridsift_core::dialect::sniff;
use gridsift_core::export::{ExportOptions, ExportReport, Selection, export};
use gridsift_core::frequency::{FrequencyOptions, FrequencyResult, FrequencyShared, frequency};
use gridsift_core::hash::hex;
use gridsift_core::index::{BuildOptions, IndexParams, SparseIndex, bootstrap, build_index};
use gridsift_core::manifest::{Manifest, Operation, OutputInfo, SelectionInfo, SourceInfo};
use gridsift_core::reader::{header_fields, locate_many, locate_records};
use gridsift_core::redact::{
    DEFAULT_HMAC_LENGTH, DEFAULT_MASK, RedactMethod, RedactRule, Redactor,
};
use gridsift_core::search::{
    PatternKind, SearchOptions, SearchOutcome, SearchQuery, SearchShared, search,
};
use gridsift_core::semantic::{Profile, ProfileOptions, SemanticType, profile, profile_rows};
use gridsift_core::sidecar::default_index_path;
use gridsift_core::sys::{boost_current_thread, group_thousands, human_bytes, peak_rss_bytes};
use gridsift_core::{HashSelection, Source};

const ROW_HEIGHT: f32 = 18.0;
const HEADER_HEIGHT: f32 = 34.0;
// Explicit grid colours: egui's default dark palette renders "strong" header
// text too dim against the striped rows.
const HEADER_TEXT: Color32 = Color32::from_gray(235);
const ROW_NUMBER_TEXT: Color32 = Color32::from_gray(120);
const CELL_TEXT: Color32 = Color32::from_gray(210);
const MATCH_TEXT: Color32 = Color32::from_rgb(255, 200, 80);
/// Rows fetched around a cache miss (biased forward: scrolling down is common).
const FETCH_BEFORE: u64 = 64;
const FETCH_TOTAL: usize = 512;
/// Matches fetched per cache miss in the filtered view.
const FETCH_FILTERED: u64 = 96;
/// Rows probed synchronously at open time, before the background index runs.
const PROBE_ROWS: usize = 1000;
/// Decoded rows kept in memory before the cache is flushed.
const CACHE_CAP: usize = 20_000;

/// `gridsift-desktop [FILE] [--search PATTERN] [--regex] [--filter] [--count COLUMN]`
struct Launch {
    file: Option<PathBuf>,
    search: Option<String>,
    regex: bool,
    filter: bool,
    /// Column index to count on launch.
    count: Option<usize>,
}

fn parse_args() -> Launch {
    let mut l = Launch {
        file: None,
        search: None,
        regex: false,
        filter: false,
        count: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--search" => l.search = args.next(),
            "--regex" => l.regex = true,
            "--filter" => l.filter = true,
            "--count" => l.count = args.next().and_then(|c| c.parse().ok()),
            _ if l.file.is_none() => l.file = Some(PathBuf::from(a)),
            _ => {}
        }
    }
    l
}

fn main() -> Result<(), eframe::Error> {
    let launch = parse_args();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("gridsift")
            .with_app_id("gridsift")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([640.0, 400.0])
            .with_drag_and_drop(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "gridsift",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            let mut app = App::default();
            if let Some(p) = &launch.file {
                app.open(&cc.egui_ctx, p);
                if let (Some(d), Some(pattern)) = (&mut app.doc, launch.search) {
                    d.search_ui.pattern = pattern;
                    d.search_ui.regex = launch.regex;
                    d.search_ui.filter = launch.filter;
                    d.start_search(&cc.egui_ctx);
                }
                if let (Some(d), Some(column)) = (&mut app.doc, launch.count) {
                    d.freq_column = column;
                    d.start_freq();
                }
            }
            Ok(Box::new(app))
        }),
    )
}

// ---------------------------------------------------------------------------
// background index build

struct BuildProgress {
    bytes: AtomicU64,
    total: u64,
    records: AtomicU64,
}

struct BuildJob {
    progress: Arc<BuildProgress>,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<std::io::Result<SparseIndex>>>,
    started: Instant,
}

impl BuildJob {
    fn spawn(
        ctx: egui::Context,
        source: Arc<Source>,
        params: IndexParams,
        shared: Arc<RwLock<SparseIndex>>,
    ) -> BuildJob {
        let progress = Arc::new(BuildProgress {
            bytes: AtomicU64::new(0),
            total: source.len(),
            records: AtomicU64::new(0),
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let (p2, c2) = (progress.clone(), cancel.clone());
        let handle = std::thread::Builder::new()
            .name("gridsift-index".into())
            .spawn(move || {
                boost_current_thread();
                let mut published = 0usize;
                let mut last_repaint = Instant::now();
                let opts = BuildOptions {
                    hash: HashSelection::SHA256,
                    cancel: Some(&c2),
                    ..BuildOptions::default()
                };
                build_index(&source, params, opts, &mut |idx, p| {
                    p2.bytes.store(p.bytes, Ordering::Relaxed);
                    p2.records.store(p.records, Ordering::Relaxed);
                    // Publish new checkpoints incrementally so the grid can
                    // reach the indexed region while the build continues.
                    if let Ok(mut w) = shared.write() {
                        if published == 0 {
                            w.checkpoints = idx.checkpoints.clone();
                        } else {
                            w.checkpoints
                                .extend_from_slice(&idx.checkpoints[published..]);
                        }
                        published = idx.checkpoints.len();
                        w.stats = idx.stats;
                        w.header = idx.header;
                    }
                    if last_repaint.elapsed() > Duration::from_millis(100) {
                        ctx.request_repaint();
                        last_repaint = Instant::now();
                    }
                })
            })
            .expect("spawn index thread");
        BuildJob {
            progress,
            cancel,
            handle: Some(handle),
            started: Instant::now(),
        }
    }

    fn is_finished(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| h.is_finished())
    }

    fn fraction(&self) -> f32 {
        if self.progress.total == 0 {
            1.0
        } else {
            self.progress.bytes.load(Ordering::Relaxed) as f32 / self.progress.total as f32
        }
    }

    /// (bytes per second, seconds remaining)
    fn rate_and_eta(&self) -> (f64, f64) {
        let done = self.progress.bytes.load(Ordering::Relaxed);
        let secs = self.started.elapsed().as_secs_f64().max(1e-3);
        let rate = done as f64 / secs;
        let left = self.progress.total.saturating_sub(done) as f64;
        (rate, if rate > 0.0 { left / rate } else { 0.0 })
    }
}

// ---------------------------------------------------------------------------
// background search

/// What the search bar holds.
#[derive(Default)]
struct SearchUi {
    pattern: String,
    regex: bool,
    ignore_case: bool,
    invert: bool,
    /// `None` = all columns.
    column: Option<usize>,
    /// Show only matching rows instead of highlighting them.
    filter: bool,
    error: Option<String>,
    focus_requested: bool,
}

impl SearchUi {
    fn query(&self) -> SearchQuery {
        SearchQuery {
            pattern: self.pattern.clone(),
            kind: if self.regex {
                PatternKind::Regex
            } else {
                PatternKind::Literal
            },
            case_insensitive: self.ignore_case,
            columns: self.column.map(|c| vec![c]),
            invert: self.invert,
        }
    }
}

struct Search {
    query: SearchQuery,
    shared: Arc<SearchShared>,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<SearchOutcome>>,
    outcome: Option<SearchOutcome>,
    started: Instant,
}

impl Search {
    fn running(&self) -> bool {
        self.handle.is_some()
    }

    fn poll(&mut self) {
        if self.handle.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(h) = self.handle.take() {
                self.outcome = h.join().ok();
            }
        }
    }

    fn rate(&self) -> f64 {
        let done = self.shared.bytes.load(Ordering::Relaxed) as f64;
        done / self.started.elapsed().as_secs_f64().max(1e-3)
    }

    fn status_line(&self) -> String {
        let n = group_thousands(self.shared.match_count());
        let what = match self.query.kind {
            PatternKind::Regex => format!("/{}/", self.query.pattern),
            PatternKind::Literal => format!("{:?}", self.query.pattern),
        };
        match &self.outcome {
            None => format!(
                "{what}: {n} matches · scanning {:.0}% · {}/s",
                self.shared.fraction() * 100.0,
                human_bytes(self.rate() as u64)
            ),
            Some(o) if o.complete => format!(
                "{what}: {n} matches in {:.2} s ({}/s, {} threads)",
                o.elapsed.as_secs_f64(),
                human_bytes((o.bytes_scanned as f64 / o.elapsed.as_secs_f64().max(1e-3)) as u64),
                o.threads
            ),
            Some(o) => match &o.error {
                Some(e) => format!("{what}: {n} matches · read error: {e}"),
                None => format!("{what}: {n} matches (cancelled)"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// background export

struct ExportJob {
    handle: Option<JoinHandle<Result<(ExportReport, PathBuf), String>>>,
    records: Arc<AtomicU64>,
    expected: u64,
    cancel: Arc<AtomicBool>,
    out: PathBuf,
}

// ---------------------------------------------------------------------------
// background value count

struct FreqJob {
    shared: Arc<FrequencyShared>,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<std::io::Result<FrequencyResult>>>,
    column: usize,
}

struct FreqView {
    column: usize,
    result: FrequencyResult,
    /// (value, count, share) ready for display.
    rows: Vec<(String, u64, f32)>,
}

// ---------------------------------------------------------------------------
// export dialog

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleChoice {
    Keep,
    Drop,
    Mask,
    Partial,
    Ip,
    Hmac,
}

impl RuleChoice {
    const ALL: [RuleChoice; 6] = [
        RuleChoice::Keep,
        RuleChoice::Drop,
        RuleChoice::Mask,
        RuleChoice::Partial,
        RuleChoice::Ip,
        RuleChoice::Hmac,
    ];

    fn label(&self) -> &'static str {
        match self {
            RuleChoice::Keep => "keep",
            RuleChoice::Drop => "drop",
            RuleChoice::Mask => "mask",
            RuleChoice::Partial => "partial",
            RuleChoice::Ip => "ip prefix",
            RuleChoice::Hmac => "hmac",
        }
    }
}

/// State of the export dialog: what to export and how to redact it.
struct ExportUi {
    open: bool,
    /// Export the matches of the current search rather than all records.
    matches: bool,
    /// One choice per column.
    choices: Vec<RuleChoice>,
    mask_text: String,
    keep: usize,
    bits: u8,
    hmac_len: usize,
    /// Kept in memory only; the manifest records a fingerprint.
    hmac_key: String,
    error: Option<String>,
}

impl Default for ExportUi {
    fn default() -> Self {
        ExportUi {
            open: false,
            matches: false,
            choices: Vec::new(),
            mask_text: DEFAULT_MASK.into(),
            keep: 3,
            bits: 24,
            hmac_len: DEFAULT_HMAC_LENGTH,
            hmac_key: String::new(),
            error: None,
        }
    }
}

impl ExportUi {
    fn show(&mut self, matches: bool, ncols: usize) {
        self.open = true;
        self.matches = matches;
        self.error = None;
        if self.choices.len() != ncols {
            self.choices = vec![RuleChoice::Keep; ncols];
        }
    }

    fn rules(&self, header: &[String]) -> Vec<RedactRule> {
        self.choices
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                let method = match c {
                    RuleChoice::Keep => return None,
                    RuleChoice::Drop => RedactMethod::Drop,
                    RuleChoice::Mask => RedactMethod::Mask {
                        replacement: self.mask_text.clone(),
                    },
                    RuleChoice::Partial => RedactMethod::Partial {
                        keep: self.keep,
                        fill: '*',
                    },
                    RuleChoice::Ip => RedactMethod::IpPrefix { bits: self.bits },
                    RuleChoice::Hmac => RedactMethod::Hmac {
                        length: self.hmac_len,
                        key_fingerprint: String::new(),
                    },
                };
                Some(RedactRule {
                    column: i,
                    name: header.get(i).cloned().unwrap_or_else(|| format!("col{i}")),
                    method,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// document

/// Decoded rows by record ordinal, filled in windows (contiguous view) or
/// batches of scattered ordinals (filtered view).
#[derive(Default)]
struct RowCache {
    rows: HashMap<u64, Vec<String>>,
}

impl RowCache {
    fn get(&self, record: u64) -> Option<&[String]> {
        self.rows.get(&record).map(Vec::as_slice)
    }

    fn len(&self) -> usize {
        self.rows.len()
    }

    fn make_room(&mut self) {
        if self.rows.len() > CACHE_CAP {
            self.rows.clear();
        }
    }

    fn decode(
        source: &Source,
        index: &SparseIndex,
        recs: &[gridsift_core::Located],
    ) -> Vec<(u64, Vec<String>)> {
        let mut fields = Vec::new();
        recs.iter()
            .map(|r| {
                r.fields(source, index, &mut fields);
                let row = fields
                    .iter()
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect();
                (r.record, row)
            })
            .collect()
    }

    /// Fetch `first .. first + count`; returns how many rows were found.
    fn fill_window(
        &mut self,
        source: &Source,
        index: &SparseIndex,
        first: u64,
        count: usize,
    ) -> usize {
        self.make_room();
        let recs = locate_records(source, index, first, count);
        let n = recs.len();
        self.rows.extend(Self::decode(source, index, &recs));
        n
    }

    /// Fetch scattered ordinals (sorted, de-duplicated).
    fn fill_many(&mut self, source: &Source, index: &SparseIndex, ordinals: &[u64]) {
        self.make_room();
        let recs = locate_many(source, index, ordinals);
        self.rows.extend(Self::decode(source, index, &recs));
    }
}

struct Document {
    path: PathBuf,
    source: Arc<Source>,
    params: IndexParams,
    index: Arc<RwLock<SparseIndex>>,
    header: Vec<String>,
    /// Rows known to exist so far (probe, then build progress).
    known_rows: u64,
    build: Option<BuildJob>,
    build_error: Option<String>,
    cache: RowCache,
    col_widths: Vec<f32>,
    goto: String,
    pending_scroll: Option<u64>,
    /// Top row of the grid in the last frame (record ordinal).
    first_visible: u64,
    search_ui: SearchUi,
    search: Option<Search>,
    export: Option<ExportJob>,
    /// Column typing: from the probe rows at first, file-wide once indexed.
    profile: Option<Profile>,
    profile_job: Option<JoinHandle<Profile>>,
    /// Column selected for value counting.
    freq_column: usize,
    freq_job: Option<FreqJob>,
    freq: Option<FreqView>,
    /// A value clicked in the count panel: (column, value) to filter by.
    pending_pivot: Option<(usize, String)>,
    export_ui: ExportUi,
    /// Open → first rows on screen.
    first_rows_in: Duration,
    index_elapsed: Option<Duration>,
    index_from_sidecar: bool,
    sidecar: Option<PathBuf>,
    status: Option<String>,
}

impl Document {
    fn open(ctx: &egui::Context, path: &Path) -> Result<Document, String> {
        let t0 = Instant::now();
        let source = Arc::new(Source::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
        let head = source.slice(0, 1 << 20);
        let sn = sniff(head, source.len());
        let mut params = IndexParams {
            dialect: sn.dialect,
            scan_start: sn.scan_start,
            ..IndexParams::default()
        };

        // A complete, matching sidecar means no build is needed at all.
        let sidecar = default_index_path(path).ok();
        let cached = sidecar
            .as_ref()
            .and_then(|p| SparseIndex::load(p).ok())
            .filter(|i| i.matches_source(source.id()) && i.stats.complete);
        let (index, from_sidecar) = match cached {
            Some(i) => {
                params = i.params;
                (i, true)
            }
            None => (bootstrap(&source, params), false),
        };
        let header: Vec<String> = match header_fields(&source, &index) {
            Some(h) => h
                .iter()
                .map(|f| String::from_utf8_lossy(f).into_owned())
                .collect(),
            None => (0..index.stats.expected_fields)
                .map(|i| format!("col{i}"))
                .collect(),
        };

        let mut cache = RowCache::default();
        let probed = cache.fill_window(&source, &index, 0, PROBE_ROWS);
        let known_rows = if from_sidecar {
            index.stats.records
        } else {
            probed as u64
        };
        let col_widths = column_widths(&header, (0..200).filter_map(|r| cache.get(r)));
        let quick_profile = profile_rows(&header, (0..probed as u64).filter_map(|r| cache.get(r)));
        let first_rows_in = t0.elapsed();

        // With a complete index already on disk there is no build to wait
        // for, so the file-wide profile starts right away.
        let profile_job = from_sidecar.then(|| {
            let (s, i, h) = (source.clone(), index.clone(), header.clone());
            std::thread::Builder::new()
                .name("gridsift-profile".into())
                .spawn(move || profile(&s, &i, &h, ProfileOptions::default()))
                .expect("spawn profile thread")
        });
        let index = Arc::new(RwLock::new(index));
        let build = (!from_sidecar)
            .then(|| BuildJob::spawn(ctx.clone(), source.clone(), params, index.clone()));
        Ok(Document {
            path: path.to_path_buf(),
            source,
            params,
            index,
            header,
            known_rows,
            build,
            build_error: None,
            cache,
            col_widths,
            goto: String::new(),
            pending_scroll: None,
            first_visible: 0,
            search_ui: SearchUi::default(),
            search: None,
            export: None,
            profile: Some(quick_profile),
            profile_job,
            freq_column: 0,
            freq_job: None,
            freq: None,
            pending_pivot: None,
            export_ui: ExportUi::default(),
            first_rows_in,
            index_elapsed: None,
            index_from_sidecar: from_sidecar,
            sidecar,
            status: None,
        })
    }

    /// Poll the background build; on completion adopt the final index and
    /// persist it.
    fn poll_build(&mut self) {
        let Some(job) = &mut self.build else { return };
        self.known_rows = self
            .known_rows
            .max(job.progress.records.load(Ordering::Relaxed));
        if !job.is_finished() {
            return;
        }
        let elapsed = job.started.elapsed();
        let handle = job.handle.take().expect("handle present until joined");
        self.build = None;
        match handle.join() {
            Ok(Ok(idx)) => {
                self.known_rows = idx.stats.records;
                let complete = idx.stats.complete;
                if complete {
                    self.spawn_profile(idx.clone());
                }
                if complete {
                    if let Some(p) = &self.sidecar {
                        if let Err(e) = idx.save(p) {
                            self.status = Some(format!("index not saved: {e}"));
                        }
                    }
                    self.index_elapsed = Some(elapsed);
                } else {
                    self.status = Some(
                        "indexing cancelled; rows beyond the indexed region are not shown".into(),
                    );
                }
                if let Ok(mut w) = self.index.write() {
                    *w = idx;
                }
            }
            Ok(Err(e)) => self.build_error = Some(e.to_string()),
            Err(_) => self.build_error = Some("index thread panicked".into()),
        }
    }

    fn poll_search(&mut self) {
        if let Some(s) = &mut self.search {
            s.poll();
        }
    }

    fn cancel_search(&mut self) {
        if let Some(s) = &self.search {
            s.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Compile the search bar's query and start it on worker threads.
    fn start_search(&mut self, ctx: &egui::Context) {
        self.cancel_search();
        self.search = None;
        self.search_ui.error = None;
        let query = self.search_ui.query();
        let compiled = match query.compile(self.params.dialect) {
            Ok(c) => c,
            Err(e) => {
                self.search_ui.error = Some(e);
                return;
            }
        };
        // Snapshot the index so the build thread is not blocked for the
        // duration of the search; the tail past the last checkpoint is still
        // scanned sequentially.
        let index = match self.index.read() {
            Ok(i) => i.clone(),
            Err(_) => return,
        };
        let shared = Arc::new(SearchShared::new(self.source.len()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (source, s2, c2, ctx2) = (
            self.source.clone(),
            shared.clone(),
            cancel.clone(),
            ctx.clone(),
        );
        let handle = std::thread::Builder::new()
            .name("gridsift-search".into())
            .spawn(move || {
                let opts = SearchOptions {
                    cancel: Some(&c2),
                    ..SearchOptions::default()
                };
                let out = search(&source, &index, &compiled, opts, &s2);
                ctx2.request_repaint();
                out
            })
            .expect("spawn search thread");
        self.search = Some(Search {
            query,
            shared,
            cancel,
            handle: Some(handle),
            outcome: None,
            started: Instant::now(),
        });
    }

    /// Re-profile from positions across the whole file, off the UI thread.
    fn spawn_profile(&mut self, index: SparseIndex) {
        let (source, header) = (self.source.clone(), self.header.clone());
        let handle = std::thread::Builder::new()
            .name("gridsift-profile".into())
            .spawn(move || profile(&source, &index, &header, ProfileOptions::default()))
            .expect("spawn profile thread");
        self.profile_job = Some(handle);
    }

    fn poll_profile(&mut self) {
        if self.profile_job.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(h) = self.profile_job.take() {
                if let Ok(p) = h.join() {
                    self.profile = Some(p);
                }
            }
        }
    }

    /// Count the values of `freq_column` over the current view (matches when
    /// filtering, else all records) on worker threads.
    fn start_freq(&mut self) {
        if let Some(j) = &self.freq_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        let index = match self.index.read() {
            Ok(i) => i.clone(),
            Err(_) => return,
        };
        let matches: Option<gridsift_core::search::MatchSet> =
            match (&self.search, self.search_ui.filter) {
                (Some(s), true) => Some(s.shared.matches.lock().expect("match set").clone()),
                _ => None,
            };
        let shared = Arc::new(FrequencyShared::new(self.source.len()));
        let cancel = Arc::new(AtomicBool::new(false));
        let column = self.freq_column;
        let (source, s2, c2) = (self.source.clone(), shared.clone(), cancel.clone());
        let handle = std::thread::Builder::new()
            .name("gridsift-freq".into())
            .spawn(move || {
                let selection = match &matches {
                    Some(m) => Selection::Matches(m),
                    None => Selection::All,
                };
                let opts = FrequencyOptions {
                    column,
                    top: 500,
                    cancel: Some(&c2),
                    ..FrequencyOptions::default()
                };
                frequency(&source, &index, selection, opts, &s2)
            })
            .expect("spawn freq thread");
        self.freq_job = Some(FreqJob {
            shared,
            cancel,
            handle: Some(handle),
            column,
        });
    }

    fn poll_freq(&mut self) {
        let Some(job) = &mut self.freq_job else {
            return;
        };
        if !job.handle.as_ref().is_some_and(|h| h.is_finished()) {
            return;
        }
        let handle = job.handle.take().expect("handle present until joined");
        let column = job.column;
        self.freq_job = None;
        match handle.join() {
            Ok(Ok(result)) if result.complete => {
                let total = result.counted.max(1) as f32;
                let rows = result
                    .top
                    .iter()
                    .map(|e| {
                        (
                            String::from_utf8_lossy(&e.value).into_owned(),
                            e.count,
                            e.count as f32 / total,
                        )
                    })
                    .collect();
                self.freq = Some(FreqView {
                    column,
                    result,
                    rows,
                });
            }
            Ok(Ok(_)) => self.status = Some("count cancelled".into()),
            Ok(Err(e)) => self.status = Some(format!("count failed: {e}")),
            Err(_) => self.status = Some("count thread panicked".into()),
        }
    }

    fn poll_export(&mut self) {
        let Some(job) = &mut self.export else { return };
        if !job.handle.as_ref().is_some_and(|h| h.is_finished()) {
            self.status = Some(format!(
                "exporting… {} / {} records → {}",
                group_thousands(job.records.load(Ordering::Relaxed)),
                group_thousands(job.expected),
                job.out.display()
            ));
            return;
        }
        let handle = job.handle.take().expect("handle present until joined");
        self.export = None;
        self.status = Some(match handle.join() {
            Ok(Ok((rep, manifest))) if rep.complete => format!(
                "exported {} records ({}) → {} · SHA-256 {} · manifest {}",
                group_thousands(rep.records),
                human_bytes(rep.bytes),
                rep.path.display(),
                rep.digests.sha256.map(|d| hex(&d)).unwrap_or_default(),
                manifest.display()
            ),
            Ok(Ok(_)) => "export cancelled; no file written".into(),
            Ok(Err(e)) => format!("export failed: {e}"),
            Err(_) => "export thread panicked".into(),
        });
    }

    /// Export the current view (matches when filtering, else all records)
    /// plus a provenance manifest, on a background thread.
    fn start_export(
        &mut self,
        out: PathBuf,
        use_matches: bool,
        rules: Vec<RedactRule>,
        hmac_key: Option<Vec<u8>>,
    ) {
        let index = match self.index.read() {
            Ok(i) if i.stats.complete && i.digests.sha256.is_some() => i.clone(),
            _ => {
                self.status = Some("export needs the finished index (wait for indexing)".into());
                return;
            }
        };
        let (matches, operations): (Option<gridsift_core::search::MatchSet>, Vec<Operation>) =
            match (&self.search, use_matches) {
                (Some(s), true) => {
                    let m = s.shared.matches.lock().expect("match set").clone();
                    let ops = vec![Operation::Search {
                        query: s.query.clone(),
                        matches: m.len(),
                    }];
                    (Some(m), ops)
                }
                _ => (None, Vec::new()),
            };
        let expected = matches.as_ref().map_or(index.stats.records, |m| m.len());
        let records = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let (source, r2, c2, out2) = (
            self.source.clone(),
            records.clone(),
            cancel.clone(),
            out.clone(),
        );
        let handle = std::thread::Builder::new()
            .name("gridsift-export".into())
            .spawn(move || {
                boost_current_thread();
                let selection = match &matches {
                    Some(m) => Selection::Matches(m),
                    None => Selection::All,
                };
                let redactor = if rules.is_empty() {
                    None
                } else {
                    Some(
                        Redactor::new(index.params.dialect, rules, hmac_key.as_deref())
                            .map_err(|e| format!("redaction: {e}"))?,
                    )
                };
                let mut operations = operations;
                if let Some(r) = &redactor {
                    operations.push(Operation::Redact {
                        policy: r.policy().clone(),
                    });
                }
                let opts = ExportOptions {
                    overwrite: true,
                    redactor: redactor.as_ref(),
                    cancel: Some(&c2),
                    ..ExportOptions::default()
                };
                let rep = export(&source, &index, selection, opts, &out2, &mut |n, _| {
                    r2.store(n, Ordering::Relaxed)
                })
                .map_err(|e| e.to_string())?;
                if !rep.complete {
                    return Ok((rep, PathBuf::new()));
                }
                let out_path = std::fs::canonicalize(&out2).unwrap_or_else(|_| out2.clone());
                let manifest = Manifest::new(
                    SourceInfo::from_source(
                        &source,
                        index.params.dialect,
                        index.digests,
                        Some(index.stats.records),
                    ),
                    operations,
                    match &matches {
                        Some(m) => SelectionInfo::Matches { records: m.len() },
                        None => SelectionInfo::All,
                    },
                    OutputInfo {
                        path: out_path.display().to_string(),
                        name: out_path
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        format: "csv".into(),
                        content: if redactor.is_some() {
                            "records-redacted"
                        } else {
                            "raw-records"
                        }
                        .into(),
                        header: index.header.is_some(),
                        terminator: "\n".into(),
                        records: rep.records,
                        size: rep.bytes,
                        sha256: rep.digests.sha256.map(|d| hex(&d)),
                        blake3: rep.digests.blake3.map(|d| hex(&d)),
                    },
                );
                let mpath = Manifest::path_for(&out2);
                manifest.write(&mpath).map_err(|e| e.to_string())?;
                Ok((rep, mpath))
            })
            .expect("spawn export thread");
        self.export = Some(ExportJob {
            handle: Some(handle),
            records,
            expected,
            cancel,
            out,
        });
    }

    fn clear_search(&mut self) {
        self.cancel_search();
        self.search = None;
        self.search_ui.filter = false;
    }
}

/// Initial column widths from header and sample rows (character-count based).
fn column_widths<'a>(header: &[String], rows: impl Iterator<Item = &'a [String]>) -> Vec<f32> {
    let mut chars: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        if r.len() > chars.len() {
            chars.resize(r.len(), 0);
        }
        for (c, v) in r.iter().enumerate() {
            chars[c] = chars[c].max(v.chars().count());
        }
    }
    chars
        .into_iter()
        .map(|n| (n as f32 * 7.4 + 16.0).clamp(56.0, 420.0))
        .collect()
}

// ---------------------------------------------------------------------------
// app

#[derive(Default)]
struct App {
    doc: Option<Document>,
    error: Option<String>,
}

impl App {
    fn open(&mut self, ctx: &egui::Context, path: &Path) {
        self.close();
        match Document::open(ctx, path) {
            Ok(d) => {
                self.doc = Some(d);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
        ctx.request_repaint();
    }

    fn open_dialog(&mut self, ctx: &egui::Context) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("Delimited text", &["csv", "tsv", "txt", "log"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            self.open(ctx, &p);
        }
    }

    fn close(&mut self) {
        if let Some(d) = &mut self.doc {
            if let Some(j) = &d.build {
                j.cancel.store(true, Ordering::Relaxed);
            }
            d.cancel_search();
            if let Some(j) = &d.export {
                j.cancel.store(true, Ordering::Relaxed);
            }
            if let Some(j) = &d.freq_job {
                j.cancel.store(true, Ordering::Relaxed);
            }
        }
        self.doc = None;
    }
}

impl eframe::App for App {
    /// Scroll offsets and widget state must not leak from one evidence file
    /// (or session) to the next.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // drag & drop
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if let Some(p) = dropped.first() {
            self.open(ctx, p);
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.open_dialog(ctx);
        }
        if let Some(d) = &mut self.doc {
            d.poll_build();
            d.poll_search();
            d.poll_export();
            d.poll_profile();
            d.poll_freq();
            if let Some((column, value)) = d.pending_pivot.take() {
                d.search_ui.pattern = value;
                d.search_ui.column = Some(column);
                d.search_ui.regex = false;
                d.search_ui.ignore_case = false;
                d.search_ui.invert = false;
                d.search_ui.filter = true;
                d.start_search(ctx);
            }
            if d.freq_job.is_some() {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            if d.profile_job.is_some() {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            if d.export.is_some() {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
                d.search_ui.focus_requested = true;
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Open…").clicked() {
                    self.open_dialog(ctx);
                }
                if self.doc.is_some() && ui.button("Close").clicked() {
                    self.close();
                }
                if let Some(d) = &mut self.doc {
                    let ready = d.build.is_none()
                        && d.export.is_none()
                        && d.index
                            .read()
                            .is_ok_and(|i| i.stats.complete && i.digests.sha256.is_some());
                    let filtered = d.search_ui.filter && d.search.is_some();
                    let label = if filtered {
                        "Export matches…"
                    } else {
                        "Export all…"
                    };
                    let resp = ui
                        .add_enabled(ready, egui::Button::new(label))
                        .on_disabled_hover_text(
                            "available once indexing and any running export have finished",
                        );
                    if resp.clicked() {
                        d.export_ui.show(filtered, d.header.len());
                    }
                }
                ui.separator();
                match &self.doc {
                    Some(d) => {
                        ui.strong(
                            d.path
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        );
                        ui.label(human_bytes(d.source.len()));
                    }
                    None => {
                        ui.label("no file open");
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    badge(ui, "STRICT OFFLINE", Color32::from_rgb(70, 130, 180));
                    badge(ui, "EVIDENCE · READ ONLY", Color32::from_rgb(46, 139, 87));
                });
            });
            if let Some(d) = &mut self.doc {
                evidence_panel(ui, d);
                ui.separator();
                search_bar(ui, ctx, d);
            }
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(e) = &self.error {
                    ui.colored_label(Color32::LIGHT_RED, e);
                } else if let Some(d) = &self.doc {
                    if let Some(e) = &d.build_error {
                        ui.colored_label(Color32::LIGHT_RED, format!("indexing failed: {e}"));
                    } else if let Some(s) = &d.status {
                        ui.colored_label(Color32::KHAKI, s);
                    } else {
                        ui.label(format!(
                            "first rows in {:.1} ms",
                            d.first_rows_in.as_secs_f64() * 1000.0
                        ));
                        if let Some(t) = d.index_elapsed {
                            ui.separator();
                            ui.label(format!("indexed in {:.2} s", t.as_secs_f64()));
                        } else if d.index_from_sidecar {
                            ui.separator();
                            ui.label("index loaded from cache");
                        }
                    }
                } else {
                    ui.label("Drop a CSV/TSV file here, or press ⌘O / Ctrl+O");
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(format!("peak RSS {}", human_bytes(peak_rss_bytes())));
                    if let Some(d) = &self.doc {
                        ui.separator();
                        ui.label(format!(
                            "{} rows cached",
                            group_thousands(d.cache.len() as u64)
                        ));
                    }
                });
            });
        });

        if let Some(d) = &mut self.doc {
            freq_panel(ctx, d);
            export_window(ctx, d);
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.inner_margin(0.0))
            .show(ctx, |ui| match &mut self.doc {
                Some(d) => grid(ui, d),
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("Drop a CSV / TSV file here\nor click Open…\n\nThe file is opened read-only and never modified.")
                                .size(20.0)
                                .color(Color32::GRAY),
                        );
                    });
                }
            });

        // keep progress displays moving while background work runs
        let busy = self
            .doc
            .as_ref()
            .is_some_and(|d| d.build.is_some() || d.search.as_ref().is_some_and(Search::running));
        if busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::NONE
        .fill(color)
        .corner_radius(3.0)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .color(Color32::WHITE)
                    .strong()
                    .size(11.0),
            );
        });
}

fn evidence_panel(ui: &mut egui::Ui, d: &mut Document) {
    let (records, complete, mismatches, lenient, unterminated, sha) = {
        let idx = d.index.read().expect("index lock");
        (
            idx.stats.records,
            idx.stats.complete,
            idx.stats.field_mismatches,
            idx.stats.lenient_quotes,
            idx.stats.unterminated_quotes,
            idx.digests.sha256.map(|h| hex(&h)),
        )
    };
    egui::Grid::new("evidence").num_columns(2).spacing([12.0, 2.0]).show(ui, |ui| {
        ui.label(RichText::new("Records").weak());
        ui.horizontal(|ui| {
            let shown = if complete { records } else { d.known_rows.max(records) };
            ui.monospace(group_thousands(shown));
            if let Some(job) = &d.build {
                let (rate, eta) = job.rate_and_eta();
                ui.add(
                    egui::ProgressBar::new(job.fraction())
                        .desired_width(220.0)
                        .text(format!("indexing {:.0}%", job.fraction() * 100.0)),
                );
                ui.label(format!("{}/s · eta {:.0} s", human_bytes(rate as u64), eta));
                if ui.small_button("Cancel").clicked() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
            } else if !complete {
                ui.label(RichText::new("(partial index)").weak());
            }
        });
        ui.end_row();

        ui.label(RichText::new("SHA-256").weak());
        match sha {
            Some(h) => {
                ui.monospace(h);
            }
            None => {
                let pct = d.build.as_ref().map_or(0.0, |j| j.fraction() * 100.0);
                ui.label(RichText::new(format!("computing… {pct:.0}%")).weak());
            }
        }
        ui.end_row();

        ui.label(RichText::new("Dialect").weak());
        let dl = d.params.dialect;
        ui.horizontal(|ui| {
            ui.monospace(format!(
                "delimiter {:?}  quote {}  header {}  fields {}",
                dl.delimiter as char,
                dl.quote.map_or("none".to_string(), |q| format!("{:?}", q as char)),
                if dl.has_header { "yes" } else { "no" },
                d.header.len()
            ));
            if mismatches + lenient + unterminated > 0 {
                ui.colored_label(
                    Color32::KHAKI,
                    format!("malformed: {mismatches} field-count, {lenient} lenient quote, {unterminated} unterminated"),
                );
            }
        });
        ui.end_row();

        ui.label(RichText::new("Columns").weak());
        ui.horizontal_wrapped(|ui| match &d.profile {
            Some(p) => {
                let mut shown = 0;
                for c in p
                    .columns
                    .iter()
                    .filter(|c| c.detected.is_indicator() || c.detected == SemanticType::Timestamp)
                {
                    if shown == 8 {
                        ui.label(RichText::new("…").weak());
                        break;
                    }
                    ui.label(RichText::new(&c.name).monospace());
                    ui.label(
                        RichText::new(format!("{} {:.0}%", c.detected.name(), c.confidence * 100.0))
                            .color(MATCH_TEXT)
                            .small(),
                    );
                    shown += 1;
                }
                if shown == 0 {
                    ui.label(RichText::new("no indicator columns detected").weak());
                }
                ui.label(
                    RichText::new(format!(
                        "(sampled {} rows{})",
                        group_thousands(p.sampled_records),
                        if p.spans_file { " across the file" } else { ", head only" }
                    ))
                    .weak(),
                );
            }
            None => {
                ui.label(RichText::new("profiling…").weak());
            }
        });
        ui.end_row();

        ui.label(RichText::new("Go to row").weak());
        ui.horizontal(|ui| {
            let resp = ui.add(egui::TextEdit::singleline(&mut d.goto).desired_width(120.0).hint_text("0-based"));
            let go = ui.button("Go").clicked() || (resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
            if go {
                if let Ok(n) = d.goto.replace([',', '_'], "").trim().parse::<u64>() {
                    let max = d.known_rows.max(records).saturating_sub(1);
                    d.pending_scroll = Some(n.min(max));
                }
            }
        });
        ui.end_row();
    });
}

fn search_bar(ui: &mut egui::Ui, ctx: &egui::Context, d: &mut Document) {
    let mut run = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Search").weak());
        let resp = ui.add(
            egui::TextEdit::singleline(&mut d.search_ui.pattern)
                .desired_width(320.0)
                .hint_text("literal text, or a regex  (⌘F / Ctrl+F)"),
        );
        if d.search_ui.focus_requested {
            resp.request_focus();
            d.search_ui.focus_requested = false;
        }
        if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
            run = true;
        }
        ui.checkbox(&mut d.search_ui.regex, "Regex");
        ui.checkbox(&mut d.search_ui.ignore_case, "Aa")
            .on_hover_text("case-insensitive");
        ui.checkbox(&mut d.search_ui.invert, "Invert")
            .on_hover_text("select records that do NOT match");
        let col_label = match d.search_ui.column {
            None => "All columns".to_string(),
            Some(c) => d
                .header
                .get(c)
                .cloned()
                .unwrap_or_else(|| format!("col{c}")),
        };
        egui::ComboBox::from_id_salt("search-column")
            .selected_text(col_label)
            .width(160.0)
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut d.search_ui.column, None, "All columns");
                for (i, name) in d.header.iter().enumerate() {
                    ui.selectable_value(&mut d.search_ui.column, Some(i), name);
                }
            });
        if ui.button("Find").clicked() {
            run = true;
        }
        if d.search.is_some() && ui.button("Clear").clicked() {
            d.clear_search();
        }
    });
    if run && !d.search_ui.pattern.is_empty() {
        d.start_search(ctx);
    }

    ui.horizontal(|ui| {
        ui.label(RichText::new("Count values of").weak());
        let name = d
            .header
            .get(d.freq_column)
            .cloned()
            .unwrap_or_else(|| format!("col{}", d.freq_column));
        egui::ComboBox::from_id_salt("freq-column")
            .selected_text(name)
            .width(200.0)
            .show_ui(ui, |ui| {
                for (i, name) in d.header.iter().enumerate() {
                    ui.selectable_value(&mut d.freq_column, i, name);
                }
            });
        let scope = if d.search_ui.filter && d.search.is_some() {
            "over the matches"
        } else {
            "over all records"
        };
        if ui.button("Count").clicked() {
            d.start_freq();
        }
        ui.label(RichText::new(scope).weak());
    });

    if let Some(e) = &d.search_ui.error {
        ui.colored_label(Color32::LIGHT_RED, format!("invalid pattern: {e}"));
    }
    let Some(s) = &d.search else { return };
    let mut next_prev: Option<Option<u64>> = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new(s.status_line()).color(MATCH_TEXT));
        if s.running() {
            ui.add(egui::ProgressBar::new(s.shared.fraction()).desired_width(160.0));
            if ui.small_button("Cancel").clicked() {
                s.cancel.store(true, Ordering::Relaxed);
            }
        }
        ui.separator();
        ui.checkbox(&mut d.search_ui.filter, "Show only matches");
        if !d.search_ui.filter {
            let m = s.shared.matches.lock().expect("match set");
            if ui.button("◀ Prev").clicked() {
                next_prev = Some(m.prev_before(d.first_visible));
            }
            if ui.button("Next ▶").clicked() {
                next_prev = Some(m.next_after(d.first_visible));
            }
        }
    });
    if let Some(target) = next_prev {
        match target {
            Some(r) => d.pending_scroll = Some(r),
            None => d.status = Some("no further match".into()),
        }
    }
}

fn grid(ui: &mut egui::Ui, d: &mut Document) {
    let filter = d.search_ui.filter && d.search.is_some();
    let Document {
        source,
        index,
        cache,
        col_widths,
        header,
        pending_scroll,
        first_visible,
        search,
        known_rows,
        profile,
        path,
        ..
    } = d;
    let idx = index.read().expect("index lock");
    // Hold the match set for the frame: `select`/`contains` per visible row.
    let matches = search
        .as_ref()
        .map(|s| s.shared.matches.lock().expect("match set"));
    let total = if filter {
        matches.as_ref().map_or(0, |m| m.len()) as usize
    } else {
        *known_rows as usize
    };
    let ncols = col_widths.len();

    let mut tb = TableBuilder::new(ui)
        .id_salt(path.as_path())
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .auto_shrink([false, false])
        .min_scrolled_height(0.0)
        .cell_layout(egui::Layout::left_to_right(Align::Center))
        .column(Column::exact(row_number_width(*known_rows as usize)));
    for w in col_widths.iter() {
        tb = tb.column(Column::initial(*w).at_least(40.0).clip(true));
    }
    if let Some(r) = pending_scroll.take() {
        // in the filtered view the scroll target is a match index, not an ordinal
        let target = if filter {
            matches.as_ref().map_or(0, |m| m.rank(r).saturating_sub(1))
        } else {
            r
        };
        tb = tb.scroll_to_row(target as usize, Some(Align::TOP));
    }
    let mut top: Option<u64> = None;
    tb.header(HEADER_HEIGHT, |mut h| {
        h.col(|ui| {
            ui.label(RichText::new("#").strong().color(HEADER_TEXT));
        });
        for c in 0..ncols {
            h.col(|ui| {
                let name = header.get(c).map_or("", String::as_str);
                let typed = profile
                    .as_ref()
                    .and_then(|p| p.column(c))
                    .map(|cp| format!("{} {:.0}%", cp.detected.name(), cp.confidence * 100.0));
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.add(
                        egui::Label::new(RichText::new(name).strong().color(HEADER_TEXT))
                            .truncate(),
                    );
                    let typed = typed.as_deref().unwrap_or("");
                    ui.add(
                        egui::Label::new(RichText::new(typed).small().color(MATCH_TEXT)).truncate(),
                    );
                });
            });
        }
    })
    .body(|body| {
        body.rows(ROW_HEIGHT, total, |mut row| {
            let k = row.index() as u64;
            let (r, is_match) = match (&matches, filter) {
                (Some(m), true) => (m.select(k).unwrap_or(k), true),
                (Some(m), false) => (k, m.contains(k)),
                (None, _) => (k, false),
            };
            if top.is_none() {
                top = Some(r);
            }
            if cache.get(r).is_none() {
                match (&matches, filter) {
                    (Some(m), true) => {
                        let ords: Vec<u64> = (k..k + FETCH_FILTERED)
                            .filter_map(|j| m.select(j))
                            .collect();
                        cache.fill_many(source, &idx, &ords);
                    }
                    _ => {
                        cache.fill_window(
                            source,
                            &idx,
                            r.saturating_sub(FETCH_BEFORE),
                            FETCH_TOTAL,
                        );
                    }
                }
            }
            row.col(|ui| {
                ui.label(
                    RichText::new(group_thousands(r))
                        .monospace()
                        .color(if is_match {
                            MATCH_TEXT
                        } else {
                            ROW_NUMBER_TEXT
                        }),
                );
            });
            let fields = cache.get(r);
            for c in 0..ncols {
                row.col(|ui| {
                    let text = fields.and_then(|f| f.get(c)).map_or("", String::as_str);
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace().color(CELL_TEXT))
                            .truncate(),
                    );
                });
            }
        });
    });
    if let Some(t) = top {
        *first_visible = t;
    }
}

/// Bottom panel with the value counts of one column; a click on a value
/// filters the grid by it.
fn freq_panel(ctx: &egui::Context, d: &mut Document) {
    if d.freq.is_none() && d.freq_job.is_none() {
        return;
    }
    egui::TopBottomPanel::bottom("freq")
        .resizable(true)
        .default_height(240.0)
        .show(ctx, |ui| {
            let (mut close, mut cancel) = (false, false);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if let Some(job) = &d.freq_job {
                    let name = d.header.get(job.column).cloned().unwrap_or_default();
                    ui.label(format!("counting {name}…"));
                    ui.add(egui::ProgressBar::new(job.shared.fraction()).desired_width(160.0));
                    if ui.small_button("Cancel").clicked() {
                        cancel = true;
                    }
                } else if let Some(v) = &d.freq {
                    let r = &v.result;
                    ui.strong(d.header.get(v.column).cloned().unwrap_or_default());
                    ui.label(format!(
                        "{} distinct{} · {} records · {} empty · {:.2} s",
                        group_thousands(r.distinct),
                        if r.exact { "" } else { " (estimated)" },
                        group_thousands(r.counted),
                        group_thousands(r.empty),
                        r.elapsed.as_secs_f64()
                    ));
                    if !r.exact {
                        ui.label(
                            RichText::new(format!(
                                "counts may be under by up to {}",
                                group_thousands(r.error_bound)
                            ))
                            .color(Color32::KHAKI),
                        );
                    }
                    ui.label(RichText::new("click a value to filter by it").weak());
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("✕").clicked() {
                        close = true;
                    }
                });
            });
            if cancel {
                if let Some(j) = &d.freq_job {
                    j.cancel.store(true, Ordering::Relaxed);
                }
            }
            if close {
                if let Some(j) = &d.freq_job {
                    j.cancel.store(true, Ordering::Relaxed);
                }
                d.freq_job = None;
                d.freq = None;
                return;
            }
            let mut clicked: Option<(usize, String)> = None;
            if let Some(v) = &d.freq {
                TableBuilder::new(ui)
                    .id_salt("freq-table")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .vscroll(true)
                    .auto_shrink([false, false])
                    .cell_layout(egui::Layout::left_to_right(Align::Center))
                    .column(Column::initial(420.0).at_least(80.0).clip(true))
                    .column(Column::exact(120.0))
                    .column(Column::exact(80.0))
                    .column(Column::remainder())
                    .header(20.0, |mut h| {
                        for t in ["value", "count", "share", ""] {
                            h.col(|ui| {
                                ui.label(RichText::new(t).strong().color(HEADER_TEXT));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(ROW_HEIGHT, v.rows.len(), |mut row| {
                            let (value, count, share) = &v.rows[row.index()];
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(value).monospace().color(CELL_TEXT),
                                    )
                                    .truncate(),
                                );
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(group_thousands(*count))
                                        .monospace()
                                        .color(CELL_TEXT),
                                );
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(format!("{:.2}%", share * 100.0))
                                        .monospace()
                                        .color(CELL_TEXT),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::ProgressBar::new(*share)
                                        .desired_width(ui.available_width().max(40.0)),
                                );
                            });
                            if row.response().clicked() {
                                clicked = Some((v.column, value.clone()));
                            }
                        });
                    });
            }
            if clicked.is_some() {
                d.pending_pivot = clicked;
            }
        });
}

/// The export dialog: selection, per-column redaction, then the save dialog.
fn export_window(ctx: &egui::Context, d: &mut Document) {
    if !d.export_ui.open {
        return;
    }
    let mut open = true;
    let mut go = false;
    let mut cancel = false;
    egui::Window::new("Export")
        .collapsible(false)
        .resizable(true)
        .default_width(620.0)
        .open(&mut open)
        .show(ctx, |ui| {
            let has_search = d.search.is_some();
            ui.horizontal(|ui| {
                ui.label(RichText::new("Records").weak());
                ui.radio_value(&mut d.export_ui.matches, false, "all");
                ui.add_enabled_ui(has_search, |ui| {
                    ui.radio_value(
                        &mut d.export_ui.matches,
                        true,
                        "matches of the current search",
                    );
                });
            });
            ui.separator();
            ui.label(RichText::new("Redaction").strong());
            ui.label(
                RichText::new(
                    "Untouched columns keep their exact bytes. Redacted columns are rewritten; \
                     the manifest records the policy (never the key).",
                )
                .weak(),
            );
            egui::ScrollArea::vertical()
                .max_height(240.0)
                .show(ui, |ui| {
                    egui::Grid::new("redact-grid")
                        .num_columns(3)
                        .spacing([12.0, 4.0])
                        .striped(true)
                        .show(ui, |ui| {
                            for (i, name) in d.header.iter().enumerate() {
                                ui.label(RichText::new(name).monospace());
                                let typed = d
                                    .profile
                                    .as_ref()
                                    .and_then(|p| p.column(i))
                                    .map_or("", |c| c.detected.name());
                                ui.label(RichText::new(typed).weak());
                                if let Some(choice) = d.export_ui.choices.get_mut(i) {
                                    egui::ComboBox::from_id_salt(("redact", i))
                                        .selected_text(choice.label())
                                        .width(110.0)
                                        .show_ui(ui, |ui| {
                                            for c in RuleChoice::ALL {
                                                ui.selectable_value(choice, c, c.label());
                                            }
                                        });
                                }
                                ui.end_row();
                            }
                        });
                });
            ui.separator();
            egui::Grid::new("redact-params")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("mask text").weak());
                    ui.text_edit_singleline(&mut d.export_ui.mask_text);
                    ui.end_row();
                    ui.label(RichText::new("partial: characters kept").weak());
                    ui.add(egui::DragValue::new(&mut d.export_ui.keep).range(0..=64));
                    ui.end_row();
                    ui.label(RichText::new("ip prefix bits").weak());
                    ui.add(egui::DragValue::new(&mut d.export_ui.bits).range(0..=128));
                    ui.end_row();
                    ui.label(RichText::new("hmac length (hex chars)").weak());
                    ui.add(egui::DragValue::new(&mut d.export_ui.hmac_len).range(1..=64));
                    ui.end_row();
                    ui.label(RichText::new("hmac key").weak());
                    ui.add(
                        egui::TextEdit::singleline(&mut d.export_ui.hmac_key)
                            .password(true)
                            .desired_width(300.0)
                            .hint_text("kept in memory only"),
                    );
                    ui.end_row();
                });
            if let Some(e) = &d.export_ui.error {
                ui.colored_label(Color32::LIGHT_RED, e);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Choose file & export…").clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
    if !open || cancel {
        d.export_ui.open = false;
        return;
    }
    if !go {
        return;
    }
    let rules = d.export_ui.rules(&d.header);
    let needs_key = rules
        .iter()
        .any(|r| matches!(r.method, RedactMethod::Hmac { .. }));
    let key = needs_key.then(|| d.export_ui.hmac_key.as_bytes().to_vec());
    // validate now so mistakes show in the dialog, not after the file picker
    if let Err(e) = Redactor::new(d.params.dialect, rules.clone(), key.as_deref()) {
        d.export_ui.error = Some(e);
        return;
    }
    let filtered = d.export_ui.matches && d.search.is_some();
    let stem = d
        .path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".into());
    let name = format!(
        "{stem}-{}{}.csv",
        if filtered { "matches" } else { "all" },
        if rules.is_empty() { "" } else { "-redacted" }
    );
    if let Some(p) = rfd::FileDialog::new()
        .set_file_name(name)
        .add_filter("CSV", &["csv"])
        .save_file()
    {
        d.export_ui.open = false;
        d.export_ui.error = None;
        d.start_export(p, filtered, rules, key);
    }
}

fn row_number_width(total: usize) -> f32 {
    let digits = group_thousands(total.max(1) as u64).len();
    (digits as f32 * 8.0 + 14.0).max(40.0)
}
