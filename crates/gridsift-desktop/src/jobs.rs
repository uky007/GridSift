//! Background work: index build, selections (search / time range, chained),
//! value counts, timelines, exports. Every job runs on its own thread and is
//! polled from the UI thread; results are never awaited on the UI thread.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use gridsift_core::export::ExportReport;
use gridsift_core::frequency::{FrequencyResult, FrequencyShared};
use gridsift_core::index::{BuildOptions, IndexParams, SparseIndex, build_index};
use gridsift_core::manifest::Operation;
use gridsift_core::search::{MatchSet, PatternKind, SearchOutcome, SearchQuery, SearchShared};
use gridsift_core::sys::{boost_current_thread, group_thousands, human_bytes, iso8601_utc};
use gridsift_core::timeline::TimelineResult;
use gridsift_core::{HashSelection, Source};

// ---------------------------------------------------------------------------
// index build

pub struct BuildProgress {
    pub bytes: AtomicU64,
    pub total: u64,
    pub records: AtomicU64,
}

pub struct BuildJob {
    pub progress: Arc<BuildProgress>,
    pub cancel: Arc<AtomicBool>,
    pub handle: Option<JoinHandle<std::io::Result<SparseIndex>>>,
    pub started: Instant,
}

impl BuildJob {
    pub fn spawn(
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

    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| h.is_finished())
    }

    pub fn fraction(&self) -> f32 {
        if self.progress.total == 0 {
            1.0
        } else {
            self.progress.bytes.load(Ordering::Relaxed) as f32 / self.progress.total as f32
        }
    }

    /// (bytes per second, seconds remaining)
    pub fn rate_and_eta(&self) -> (f64, f64) {
        let done = self.progress.bytes.load(Ordering::Relaxed);
        let secs = self.started.elapsed().as_secs_f64().max(1e-3);
        let rate = done as f64 / secs;
        let left = self.progress.total.saturating_sub(done) as f64;
        (rate, if rate > 0.0 { left / rate } else { 0.0 })
    }
}

// ---------------------------------------------------------------------------
// selections

/// One step of a selection.
#[derive(Clone, Debug)]
pub enum SelectionOp {
    Search(SearchQuery),
    /// Records whose timestamp column is in `from..to` (Unix seconds).
    TimeRange {
        column: usize,
        name: String,
        from: i64,
        to: i64,
    },
}

fn short_time(secs: i64) -> String {
    let iso = iso8601_utc(secs.max(0) as u64);
    format!("{} {}", &iso[5..10], &iso[11..16])
}

impl SelectionOp {
    /// Compact text for a lineage chip.
    pub fn describe(&self, header: &[String]) -> String {
        match self {
            SelectionOp::Search(q) => {
                let pat = match q.kind {
                    PatternKind::Regex => format!("/{}/", q.pattern),
                    PatternKind::Literal => format!("{:?}", q.pattern),
                };
                let mut s = pat;
                if q.case_insensitive {
                    s.push_str(" (Aa)");
                }
                if q.invert {
                    s = format!("not {s}");
                }
                if let Some(cols) = &q.columns {
                    if let Some(&c) = cols.first() {
                        let name = header.get(c).cloned().unwrap_or_else(|| format!("col{c}"));
                        s = format!("{s} in {name}");
                    }
                }
                s
            }
            SelectionOp::TimeRange { name, from, to, .. } => {
                format!("{name} {} → {}", short_time(*from), short_time(*to))
            }
        }
    }

    pub fn manifest(&self, matches: u64) -> Operation {
        match self {
            SelectionOp::Search(q) => Operation::Search {
                query: q.clone(),
                matches,
            },
            SelectionOp::TimeRange {
                column,
                name,
                from,
                to,
            } => Operation::TimeRange {
                column: *column,
                name: name.clone(),
                from: iso8601_utc((*from).max(0) as u64),
                to: iso8601_utc((*to).max(0) as u64),
                matches,
            },
        }
    }
}

/// A selection step with its match set, linked to the step it was nested in.
/// Nodes are shared (`Arc`) so a chip can revert to an ancestor without
/// rescanning.
pub struct SelectionNode {
    pub parent: Option<Arc<SelectionNode>>,
    pub op: SelectionOp,
    pub shared: Arc<SearchShared>,
    pub cancel: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<SearchOutcome>>>,
    outcome: Mutex<Option<SearchOutcome>>,
    pub started: Instant,
}

impl SelectionNode {
    pub fn new(
        parent: Option<Arc<SelectionNode>>,
        op: SelectionOp,
        shared: Arc<SearchShared>,
        cancel: Arc<AtomicBool>,
        handle: JoinHandle<SearchOutcome>,
    ) -> Arc<SelectionNode> {
        Arc::new(SelectionNode {
            parent,
            op,
            shared,
            cancel,
            handle: Mutex::new(Some(handle)),
            outcome: Mutex::new(None),
            started: Instant::now(),
        })
    }

    pub fn running(&self) -> bool {
        self.handle.lock().map(|h| h.is_some()).unwrap_or(false)
    }

    pub fn poll(&self) {
        let Ok(mut h) = self.handle.lock() else {
            return;
        };
        if h.as_ref().is_some_and(|j| j.is_finished()) {
            if let Some(j) = h.take() {
                if let Ok(mut o) = self.outcome.lock() {
                    *o = j.join().ok();
                }
            }
        }
    }

    pub fn outcome(&self) -> Option<SearchOutcome> {
        self.outcome.lock().ok().and_then(|o| o.clone())
    }

    /// Block until the scan has finished (worker threads only, never the
    /// UI thread): jobs that nest in a selection wait for it here.
    pub fn wait(&self) {
        loop {
            self.poll();
            if !self.running() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A snapshot of the match set.
    pub fn matches(&self) -> MatchSet {
        self.shared.matches.lock().expect("match set").clone()
    }

    pub fn count(&self) -> u64 {
        self.shared.match_count()
    }

    pub fn rate(&self) -> f64 {
        let done = self.shared.bytes.load(Ordering::Relaxed) as f64;
        done / self.started.elapsed().as_secs_f64().max(1e-3)
    }

    /// Root first, this node last.
    pub fn lineage(self: &Arc<Self>) -> Vec<Arc<SelectionNode>> {
        let mut chain = Vec::new();
        let mut cur = Some(self.clone());
        while let Some(n) = cur {
            cur = n.parent.clone();
            chain.push(n);
        }
        chain.reverse();
        chain
    }

    /// Every step as a manifest operation, in application order.
    pub fn ops(self: &Arc<Self>) -> Vec<Operation> {
        self.lineage()
            .iter()
            .map(|n| n.op.manifest(n.count()))
            .collect()
    }

    pub fn status_line(&self) -> String {
        let n = group_thousands(self.count());
        match self.outcome() {
            None => format!(
                "{n} matches · scanning {:.0}% · {}/s",
                self.shared.fraction() * 100.0,
                human_bytes(self.rate() as u64)
            ),
            Some(o) if o.complete => format!(
                "{n} matches in {:.2} s ({}/s, {} thread{})",
                o.elapsed.as_secs_f64(),
                human_bytes((o.bytes_scanned as f64 / o.elapsed.as_secs_f64().max(1e-3)) as u64),
                o.threads,
                if o.threads == 1 { "" } else { "s" }
            ),
            Some(o) => match &o.error {
                Some(e) => format!("{n} matches · read error: {e}"),
                None => format!("{n} matches (cancelled)"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// value counts

pub struct FreqJob {
    pub shared: Arc<FrequencyShared>,
    pub cancel: Arc<AtomicBool>,
    pub handle: Option<JoinHandle<std::io::Result<FrequencyResult>>>,
    pub column: usize,
    /// The selection the count is restricted to, if any.
    pub base: Option<Arc<SelectionNode>>,
}

pub struct FreqView {
    pub column: usize,
    pub result: FrequencyResult,
    /// (value, count, share) ready for display.
    pub rows: Vec<(String, u64, f32)>,
    /// Records in the selection the count was restricted to.
    pub base: Option<u64>,
}

// ---------------------------------------------------------------------------
// timeline

pub struct TimelineJob {
    pub shared: Arc<FrequencyShared>,
    pub cancel: Arc<AtomicBool>,
    pub handle: Option<JoinHandle<std::io::Result<TimelineResult>>>,
    pub column: usize,
    /// The selection the timeline is restricted to, if any.
    pub base: Option<Arc<SelectionNode>>,
}

pub struct TimelineView {
    pub column: usize,
    pub result: TimelineResult,
    /// Records in the selection the timeline was restricted to.
    pub base: Option<u64>,
    /// Display bucket width in seconds.
    pub width: i64,
    pub auto: bool,
    pub bars: Vec<(i64, u64)>,
    /// Selected time range in plot coordinates (Unix seconds).
    pub sel: Option<(f64, f64)>,
    pub drag_from: Option<f64>,
}

impl TimelineView {
    pub fn new(column: usize, result: TimelineResult, base: Option<u64>) -> TimelineView {
        let width = result.auto_width(120);
        let bars = result.rebucket(width);
        TimelineView {
            column,
            result,
            base,
            width,
            auto: true,
            bars,
            sel: None,
            drag_from: None,
        }
    }

    pub fn set_width(&mut self, width: Option<i64>) {
        match width {
            Some(w) => {
                self.width = w.max(self.result.resolution);
                self.auto = false;
            }
            None => {
                self.width = self.result.auto_width(120);
                self.auto = true;
            }
        }
        self.bars = self.result.rebucket(self.width);
        self.sel = None;
    }

    /// The selection snapped outwards to bucket boundaries.
    pub fn snapped(&self) -> Option<(i64, i64)> {
        let (a, b) = self.sel?;
        let w = self.width as f64;
        let from = (a / w).floor() as i64 * self.width;
        let to = (b / w).ceil() as i64 * self.width;
        (to > from).then_some((from, to))
    }
}

// ---------------------------------------------------------------------------
// export

pub struct ExportJob {
    pub handle: Option<JoinHandle<Result<(ExportReport, PathBuf), String>>>,
    pub records: Arc<AtomicU64>,
    pub expected: u64,
    pub cancel: Arc<AtomicBool>,
    pub out: PathBuf,
}
