//! An open evidence file and everything the UI knows about it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;
use gridsift_core::Source;
use gridsift_core::dialect::sniff;
use gridsift_core::enrich::{EnrichRule, Enrichment, GeoIpDb, GeoProvider, LookupTable, Provider};
use gridsift_core::export::{ExportOptions, Selection, export_pending};
use gridsift_core::frequency::{FrequencyOptions, FrequencyShared, frequency};
use gridsift_core::hash::{Digests, HashSelection, hash_source, hex};
use gridsift_core::index::{IndexParams, SparseIndex, bootstrap};
use gridsift_core::manifest::{Manifest, Operation, OutputInfo, SelectionInfo, SourceInfo};
use gridsift_core::reader::header_fields;
use gridsift_core::redact::{
    DEFAULT_HMAC_LENGTH, DEFAULT_MASK, RedactMethod, RedactRule, Redactor,
};
use gridsift_core::search::{
    MatchSet, PatternKind, SearchOptions, SearchOutcome, SearchQuery, SearchShared, search,
};
use gridsift_core::semantic::{Profile, ProfileOptions, SemanticType, profile, profile_rows};
use gridsift_core::sidecar::default_index_path;
use gridsift_core::sys::{boost_current_thread, group_thousands, human_bytes};
use gridsift_core::timeline::{TimelineOptions, current_year, select_time_range, timeline};

use crate::cache::RowCache;
use crate::jobs::{
    BuildJob, ChartKind, Dashboard, ExportJob, FreqJob, FreqView, Panel, SelectionNode,
    SelectionOp, TimelineJob, TimelineView,
};

/// Rows probed synchronously at open time, before the background index runs.
const PROBE_ROWS: usize = 1000;

// ---------------------------------------------------------------------------
// UI state that belongs to a document

/// What the search field holds.
#[derive(Default)]
pub struct SearchUi {
    pub pattern: String,
    pub regex: bool,
    /// Whole-field equality (what a value-count pivot uses).
    pub exact: bool,
    pub ignore_case: bool,
    pub invert: bool,
    /// `None` = all columns.
    pub column: Option<usize>,
    /// Show only the selected rows instead of highlighting them.
    pub show_only: bool,
    pub error: Option<String>,
    pub focus_requested: bool,
}

impl SearchUi {
    pub fn kind(&self) -> PatternKind {
        if self.exact {
            PatternKind::Exact
        } else if self.regex {
            PatternKind::Regex
        } else {
            PatternKind::Literal
        }
    }

    pub fn query(&self) -> SearchQuery {
        SearchQuery {
            pattern: self.pattern.clone(),
            kind: self.kind(),
            case_insensitive: self.ignore_case,
            columns: self.column.map(|c| vec![c]),
            invert: self.invert,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleChoice {
    Keep,
    Drop,
    Mask,
    Partial,
    Ip,
    Hmac,
}

impl RuleChoice {
    pub const ALL: [RuleChoice; 6] = [
        RuleChoice::Keep,
        RuleChoice::Drop,
        RuleChoice::Mask,
        RuleChoice::Partial,
        RuleChoice::Ip,
        RuleChoice::Hmac,
    ];

    pub fn label(&self) -> &'static str {
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
pub struct ExportUi {
    pub open: bool,
    /// One choice per source column.
    pub choices: Vec<RuleChoice>,
    pub mask_text: String,
    pub keep: usize,
    pub bits: u8,
    pub hmac_len: usize,
    /// Kept in memory only; the manifest records a fingerprint.
    pub hmac_key: String,
    pub include_derived: bool,
    pub error: Option<String>,
}

impl Default for ExportUi {
    fn default() -> Self {
        ExportUi {
            open: false,
            choices: Vec::new(),
            mask_text: DEFAULT_MASK.into(),
            keep: 3,
            bits: 24,
            hmac_len: DEFAULT_HMAC_LENGTH,
            hmac_key: String::new(),
            include_derived: true,
            error: None,
        }
    }
}

impl ExportUi {
    pub fn show(&mut self, ncols: usize) {
        self.open = true;
        self.error = None;
        if self.choices.len() != ncols {
            self.choices = vec![RuleChoice::Keep; ncols];
        }
    }

    pub fn rules(&self, header: &[String]) -> Vec<RedactRule> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderChoice {
    GeoIp,
    Domain,
    Lookup,
}

impl ProviderChoice {
    pub const ALL: [ProviderChoice; 3] = [
        ProviderChoice::GeoIp,
        ProviderChoice::Domain,
        ProviderChoice::Lookup,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ProviderChoice::GeoIp => "GeoIP / ASN (.mmdb)",
            ProviderChoice::Domain => "Domain (public suffix list)",
            ProviderChoice::Lookup => "Lookup (local CSV)",
        }
    }
}

/// State of the enrichment dialog: the rules being assembled.
pub struct EnrichUi {
    pub open: bool,
    pub column: usize,
    pub choice: ProviderChoice,
    pub path: Option<PathBuf>,
    pub key: String,
    pub values: String,
    pub rules: Vec<EnrichRule>,
    pub error: Option<String>,
    /// A dataset being opened on a worker thread (an MMDB or a lookup CSV
    /// can be large; the UI thread never reads it).
    pub loading: Option<JoinHandle<Result<EnrichRule, String>>>,
}

impl Default for EnrichUi {
    fn default() -> Self {
        EnrichUi {
            open: false,
            column: 0,
            choice: ProviderChoice::GeoIp,
            path: None,
            key: String::new(),
            values: String::new(),
            rules: Vec::new(),
            error: None,
            loading: None,
        }
    }
}

impl EnrichUi {
    /// Snapshot of the "add" section, owned so it can be built off-thread.
    pub fn spec(&self, header: &[String]) -> RuleSpec {
        RuleSpec {
            column: self.column,
            name: header
                .get(self.column)
                .cloned()
                .unwrap_or_else(|| format!("col{}", self.column)),
            choice: self.choice,
            path: self.path.clone(),
            key: self.key.trim().to_string(),
            values: self
                .values
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// Start building the rule on a worker thread.
    pub fn start_loading(&mut self, header: &[String]) {
        if self.loading.is_some() {
            return;
        }
        self.error = None;
        let spec = self.spec(header);
        let handle = std::thread::Builder::new()
            .name("gridsift-enrich-load".into())
            .spawn(move || spec.build())
            .expect("spawn enrich thread");
        self.loading = Some(handle);
    }

    /// Collect a finished load into the rule list.
    pub fn poll_loading(&mut self) {
        if !self.loading.as_ref().is_some_and(|h| h.is_finished()) {
            return;
        }
        if let Some(h) = self.loading.take() {
            match h.join() {
                Ok(Ok(rule)) => {
                    self.rules.push(rule);
                    self.error = None;
                }
                Ok(Err(e)) => self.error = Some(e),
                Err(_) => self.error = Some("loading the dataset panicked".into()),
            }
        }
    }
}

/// Everything needed to build one enrichment rule.
#[derive(Clone, Debug)]
pub struct RuleSpec {
    pub column: usize,
    pub name: String,
    pub choice: ProviderChoice,
    pub path: Option<PathBuf>,
    pub key: String,
    pub values: Vec<String>,
}

impl RuleSpec {
    /// Open the dataset (which fingerprints it) and build the rule.
    pub fn build(self) -> Result<EnrichRule, String> {
        let provider = match self.choice {
            ProviderChoice::Domain => Provider::Domain,
            ProviderChoice::GeoIp => {
                let p = self.path.as_ref().ok_or("choose an .mmdb file")?;
                let db: Arc<dyn GeoProvider> =
                    Arc::new(GeoIpDb::open(p).map_err(|e| e.to_string())?);
                Provider::GeoIp(db)
            }
            ProviderChoice::Lookup => {
                let p = self.path.as_ref().ok_or("choose a CSV file")?;
                if self.key.is_empty() {
                    return Err("the key column is required".into());
                }
                let t = LookupTable::load(p, &self.key, &self.values).map_err(|e| e.to_string())?;
                Provider::Lookup(Arc::new(t))
            }
        };
        Ok(EnrichRule {
            column: self.column,
            name: self.name,
            provider,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockTab {
    Dashboard,
    Timeline,
    Values,
    Profile,
}

// ---------------------------------------------------------------------------
// the document

pub struct Document {
    pub path: PathBuf,
    pub source: Arc<Source>,
    pub params: IndexParams,
    pub index: Arc<RwLock<SparseIndex>>,
    pub header: Vec<String>,
    /// Rows known to exist so far (probe, then build progress).
    pub known_rows: u64,
    pub build: Option<BuildJob>,
    pub build_error: Option<String>,
    pub cache: RowCache,
    pub col_widths: Vec<f32>,
    pub goto: String,
    pub pending_scroll: Option<u64>,
    /// Top row of the grid in the last frame (record ordinal).
    pub first_visible: u64,

    pub search_ui: SearchUi,
    /// The current selection (a chain of nested steps), if any.
    pub selection: Option<Arc<SelectionNode>>,

    pub export: Option<ExportJob>,
    pub export_ui: ExportUi,

    /// Column typing: from the probe rows at first, file-wide once indexed.
    pub profile: Option<Profile>,
    pub profile_job: Option<JoinHandle<Profile>>,

    pub enrichment: Option<Arc<Enrichment>>,
    pub derived_names: Vec<String>,
    pub enrich_ui: EnrichUi,

    pub timeline_job: Option<TimelineJob>,
    pub timeline: Option<TimelineView>,
    pub freq_job: Option<FreqJob>,
    pub freq: Option<FreqView>,
    pub dock_tab: DockTab,
    pub dock_open: bool,
    pub dashboard: Dashboard,

    /// Open → first rows on screen.
    pub first_rows_in: Duration,
    pub index_elapsed: Option<Duration>,
    pub index_from_sidecar: bool,
    pub sidecar: Option<PathBuf>,
    pub status: Option<String>,

    /// A cached index without a digest gets one from this pass.
    pub digest_job: Option<DigestJob>,
    /// The source's size or mtime changed after it was opened: the index,
    /// digest and every selection are stale. Set by [`Document::poll_all`].
    pub source_changed: bool,
    last_source_check: Instant,
}

/// Hash-only pass for a sidecar that was built without a digest.
pub struct DigestJob {
    pub cancel: Arc<AtomicBool>,
    pub handle: Option<JoinHandle<std::io::Result<Option<Digests>>>>,
}

impl Document {
    pub fn open(ctx: &egui::Context, path: &Path) -> Result<Document, String> {
        let t0 = Instant::now();
        let source = Arc::new(Source::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
        let head = source.slice(0, 1 << 20);
        let sn = sniff(head, source.len());
        let params = IndexParams {
            dialect: sn.dialect,
            scan_start: sn.scan_start,
            ..IndexParams::default()
        };

        // A complete sidecar for this file *and* this dialect means no
        // build is needed; a missing digest is computed separately below.
        let sidecar = default_index_path(path, params.dialect).ok();
        let cached = sidecar
            .as_ref()
            .and_then(|p| SparseIndex::load(p).ok())
            .filter(|i| {
                i.matches_source(source.id())
                    && i.stats.complete
                    && i.params.dialect == params.dialect
            });
        let (index, from_sidecar) = match cached {
            Some(i) => (i, true),
            None => (bootstrap(&source, params), false),
        };
        let needs_digest = from_sidecar && index.digests.sha256.is_none();
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
        let probed = cache.fill_window(&source, &index, None, 0, PROBE_ROWS);
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
        let digest_job = needs_digest.then(|| {
            let cancel = Arc::new(AtomicBool::new(false));
            let (s, c, ctx2) = (source.clone(), cancel.clone(), ctx.clone());
            let handle = std::thread::Builder::new()
                .name("gridsift-digest".into())
                .spawn(move || {
                    boost_current_thread();
                    let r = hash_source(&s, HashSelection::SHA256, 8 << 20, Some(&c));
                    ctx2.request_repaint();
                    r
                })
                .expect("spawn digest thread");
            DigestJob {
                cancel,
                handle: Some(handle),
            }
        });
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
            selection: None,
            export: None,
            export_ui: ExportUi::default(),
            profile: Some(quick_profile),
            profile_job,
            enrichment: None,
            derived_names: Vec::new(),
            enrich_ui: EnrichUi::default(),
            timeline_job: None,
            timeline: None,
            freq_job: None,
            freq: None,
            dock_tab: DockTab::Dashboard,
            dock_open: false,
            dashboard: Dashboard::default(),
            first_rows_in,
            index_elapsed: None,
            index_from_sidecar: from_sidecar,
            sidecar,
            status: None,
            digest_job,
            source_changed: false,
            last_source_check: Instant::now(),
        })
    }

    // -- names and columns -------------------------------------------------

    /// Name of a source or derived column.
    pub fn column_name(&self, i: usize) -> String {
        self.header
            .get(i)
            .cloned()
            .or_else(|| {
                i.checked_sub(self.header.len())
                    .and_then(|k| self.derived_names.get(k))
                    .cloned()
            })
            .unwrap_or_else(|| format!("col{i}"))
    }

    pub fn column_count(&self) -> usize {
        self.header.len() + self.derived_names.len()
    }

    /// The first column the profile typed as a timestamp, if any.
    pub fn timestamp_column(&self) -> Option<usize> {
        self.profile
            .as_ref()?
            .columns
            .iter()
            .find(|c| c.detected == SemanticType::Timestamp)
            .map(|c| c.index)
    }

    /// Records are being filtered to the selection.
    pub fn filtering(&self) -> bool {
        self.search_ui.show_only && self.selection.is_some()
    }

    pub fn busy(&self) -> bool {
        self.build.is_some()
            || self.selection.as_ref().is_some_and(|s| s.running())
            || self.freq_job.is_some()
            || self.timeline_job.is_some()
            || self.export.is_some()
            || self.profile_job.is_some()
            || self.digest_job.is_some()
            || self.dashboard.running()
    }

    pub fn index_complete(&self) -> bool {
        self.index
            .read()
            .is_ok_and(|i| i.stats.complete && i.digests.sha256.is_some())
    }

    /// Every step of the current selection finished normally (or there is
    /// no selection being applied).
    pub fn selection_complete(&self) -> bool {
        self.scan_base().is_none_or(|s| s.lineage_complete())
    }

    /// Why an export is not possible right now (for the disabled button).
    pub fn export_blocker(&self) -> Option<&'static str> {
        if self.source_changed {
            Some("the source file changed since it was opened; reopen it")
        } else if !self.index_complete() {
            Some("available once indexing (and the SHA-256) has finished")
        } else if self.export.is_some() {
            Some("an export is already running")
        } else if self.selection_running() {
            Some("the current scan is still running")
        } else if !self.selection_complete() {
            Some("a step of the selection was cancelled or failed; remove it first")
        } else {
            None
        }
    }

    /// Refuse to start a scan when the file on disk is no longer what was
    /// opened (index offsets and digest would be meaningless).
    fn guard_source(&mut self) -> bool {
        self.check_source(true);
        if self.source_changed {
            self.status = Some("the source file changed since it was opened; reopen it".into());
        }
        !self.source_changed
    }

    /// Metadata check of the source (size and mtime); every two seconds
    /// from the UI, or on demand before a scan.
    fn check_source(&mut self, force: bool) {
        if self.source_changed
            || (!force && self.last_source_check.elapsed() < Duration::from_secs(2))
        {
            return;
        }
        self.last_source_check = Instant::now();
        if !self.source.verify_unchanged().unwrap_or(false) {
            self.source_changed = true;
            self.cancel_all();
            self.status = Some(
                "SOURCE CHANGED on disk: the index, digest and selection are stale — reopen the file"
                    .into(),
            );
        }
    }

    // -- polling -----------------------------------------------------------

    pub fn poll_all(&mut self) {
        self.check_source(false);
        self.poll_build();
        self.poll_digest();
        self.poll_profile();
        if let Some(s) = &self.selection {
            s.poll();
        }
        self.poll_freq();
        self.poll_timeline();
        self.poll_dashboard();
        self.poll_export();
    }

    fn poll_digest(&mut self) {
        let Some(job) = &mut self.digest_job else {
            return;
        };
        if !job.handle.as_ref().is_some_and(|h| h.is_finished()) {
            return;
        }
        let handle = job.handle.take().expect("handle present until joined");
        self.digest_job = None;
        match handle.join() {
            Ok(Ok(Some(d))) => {
                let saved = self.index.write().ok().map(|mut w| {
                    w.digests = d;
                    w.clone()
                });
                if let (Some(idx), Some(p)) = (saved, &self.sidecar)
                    && let Err(e) = idx.save_for(&self.source, p)
                {
                    self.status = Some(format!("index not saved: {e}"));
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => self.status = Some(format!("hashing failed: {e}")),
            Err(_) => self.status = Some("hash thread panicked".into()),
        }
    }

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
                    if let Some(p) = &self.sidecar
                        && let Err(e) = idx.save_for(&self.source, p)
                    {
                        self.status = Some(format!("index not saved: {e}"));
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
        if self.profile_job.as_ref().is_some_and(|h| h.is_finished())
            && let Some(h) = self.profile_job.take()
            && let Ok(p) = h.join()
        {
            self.profile = Some(p);
        }
    }

    // -- selections --------------------------------------------------------

    /// The selection that analyses (counts, timelines, exports) are
    /// restricted to: the current one when filtering, else none. It may
    /// still be running; workers wait for it.
    fn scan_base(&self) -> Option<Arc<SelectionNode>> {
        self.search_ui.show_only.then(|| self.selection.clone())?
    }

    /// The finished step a new selection step nests in. A step that is
    /// still running is cancelled and replaced by the new one. A parent
    /// that was cancelled or failed holds a partial match set, so nesting
    /// in it is refused (`Err` carries the message for the status bar).
    fn nesting_parent(&mut self) -> Result<(Option<MatchSet>, Option<Arc<SelectionNode>>), String> {
        let Some(s) = self.scan_base() else {
            self.cancel_running_selection();
            return Ok((None, None));
        };
        let parent = if s.running() {
            s.cancel.store(true, Ordering::Relaxed);
            s.parent.clone()
        } else {
            Some(s)
        };
        if let Some(p) = &parent
            && !p.lineage_complete()
        {
            return Err(
                    "the current selection has a cancelled or failed step; remove it (×) before searching within it"
                        .into(),
                );
        }
        let base = parent.as_ref().map(|p| p.matches());
        Ok((base, parent))
    }

    pub fn selection_running(&self) -> bool {
        self.selection.as_ref().is_some_and(|s| s.running())
    }

    fn index_snapshot(&self) -> Option<SparseIndex> {
        self.index.read().ok().map(|i| i.clone())
    }

    /// Cancel the running scan (if any) without dropping its ancestors.
    fn cancel_running_selection(&mut self) {
        if let Some(s) = &self.selection
            && s.running()
        {
            s.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn start_search(&mut self, ctx: &egui::Context) {
        self.search_ui.error = None;
        let query = self.search_ui.query();
        let compiled = match query.compile(self.params.dialect) {
            Ok(c) => c,
            Err(e) => {
                self.search_ui.error = Some(e);
                return;
            }
        };
        if !self.guard_source() {
            return;
        }
        let Some(index) = self.index_snapshot() else {
            return;
        };
        let (base, parent) = match self.nesting_parent() {
            Ok(x) => x,
            Err(e) => {
                self.status = Some(e);
                return;
            }
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
                if let Some(base) = &base
                    && let Ok(mut m) = s2.matches.lock()
                {
                    m.intersect_with(base);
                }
                ctx2.request_repaint();
                out
            })
            .expect("spawn search thread");
        self.selection = Some(SelectionNode::new(
            parent,
            SelectionOp::Search(query),
            shared,
            cancel,
            handle,
        ));
        self.search_ui.show_only = true;
    }

    /// Select the records whose `column` timestamp is in `from..to`, within
    /// the current selection when filtering.
    pub fn start_time_range(&mut self, ctx: &egui::Context, column: usize, from: i64, to: i64) {
        if !self.guard_source() {
            return;
        }
        let Some(index) = self.index_snapshot() else {
            return;
        };
        let (base, parent) = match self.nesting_parent() {
            Ok(x) => x,
            Err(e) => {
                self.status = Some(e);
                return;
            }
        };
        let reference_year = current_year();
        let shared = Arc::new(SearchShared::new(self.source.len()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (source, s2, c2, ctx2) = (
            self.source.clone(),
            shared.clone(),
            cancel.clone(),
            ctx.clone(),
        );
        let handle = std::thread::Builder::new()
            .name("gridsift-timerange".into())
            .spawn(move || {
                let opts = TimelineOptions {
                    column,
                    reference_year,
                    cancel: Some(&c2),
                    ..TimelineOptions::default()
                };
                let selection = match &base {
                    Some(m) => Selection::Matches(m),
                    None => Selection::All,
                };
                let out = select_time_range(&source, &index, selection, from, to, opts, &s2);
                ctx2.request_repaint();
                out.unwrap_or_else(|e| SearchOutcome {
                    complete: false,
                    records_scanned: 0,
                    bytes_scanned: 0,
                    elapsed: Duration::ZERO,
                    ranges: 0,
                    threads: 0,
                    error: Some(e.to_string()),
                })
            })
            .expect("spawn time-range thread");
        let op = SelectionOp::TimeRange {
            column,
            name: self.column_name(column),
            from,
            to,
            reference_year,
        };
        self.selection = Some(SelectionNode::new(parent, op, shared, cancel, handle));
        self.search_ui.show_only = true;
    }

    /// Make an ancestor (or any node of the chain) the current selection.
    pub fn revert_to(&mut self, node: Arc<SelectionNode>) {
        if let Some(cur) = &self.selection
            && !Arc::ptr_eq(cur, &node)
            && cur.running()
        {
            cur.cancel.store(true, Ordering::Relaxed);
        }
        self.selection = Some(node);
        self.cache.clear();
    }

    /// Drop the last step.
    pub fn pop_selection(&mut self) {
        let parent = self.selection.as_ref().and_then(|s| s.parent.clone());
        match parent {
            Some(p) => self.revert_to(p),
            None => self.clear_selection(),
        }
    }

    pub fn clear_selection(&mut self) {
        self.cancel_running_selection();
        self.selection = None;
        self.cache.clear();
    }

    // -- value counts ------------------------------------------------------

    pub fn start_freq(&mut self, column: usize) {
        if let Some(j) = &self.freq_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        if !self.guard_source() {
            return;
        }
        self.freq_job = self.spawn_freq(column, 500);
        self.dock_tab = DockTab::Values;
        self.dock_open = true;
    }

    /// Count the values of `column` over the current selection on a worker
    /// thread; the caller has checked the source. Used by the Values tab
    /// and by every dashboard panel.
    fn spawn_freq(&self, column: usize, top: usize) -> Option<FreqJob> {
        let index = self.index_snapshot()?;
        let base = self.scan_base();
        let shared = Arc::new(FrequencyShared::new(self.source.len()));
        let cancel = Arc::new(AtomicBool::new(false));
        let enrichment = self.enrichment.clone();
        let (source, s2, c2, b2) = (
            self.source.clone(),
            shared.clone(),
            cancel.clone(),
            base.clone(),
        );
        let handle = std::thread::Builder::new()
            .name("gridsift-freq".into())
            .spawn(move || {
                // nest in the selection once its scan has finished — and
                // only if it finished properly
                let matches = b2.as_ref().map(|n| {
                    n.wait();
                    n.matches()
                });
                if b2.as_ref().is_some_and(|n| !n.lineage_complete()) {
                    return Err(std::io::Error::other(
                        "the selection has a cancelled or failed step",
                    ));
                }
                let selection = match &matches {
                    Some(m) => Selection::Matches(m),
                    None => Selection::All,
                };
                let opts = FrequencyOptions {
                    column,
                    top,
                    enrichment: enrichment.as_deref(),
                    cancel: Some(&c2),
                    ..FrequencyOptions::default()
                };
                frequency(&source, &index, selection, opts, &s2)
            })
            .expect("spawn freq thread");
        Some(FreqJob {
            shared,
            cancel,
            handle: Some(handle),
            column,
            base,
        })
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
        let base = job.base.as_ref().map(|n| n.count());
        self.freq_job = None;
        match handle.join() {
            Ok(Ok(result)) if result.complete => {
                self.freq = Some(FreqView {
                    column,
                    rows: freq_rows(&result),
                    result,
                    base,
                });
            }
            Ok(Ok(_)) => self.status = Some("count cancelled".into()),
            Ok(Err(e)) => self.status = Some(format!("count failed: {e}")),
            Err(_) => self.status = Some("count thread panicked".into()),
        }
    }

    // -- dashboard ---------------------------------------------------------

    /// Show the dashboard, building it from the column profile the first
    /// time.
    pub fn open_dashboard(&mut self) {
        if self.dashboard.panels.is_empty() && !self.dashboard.auto_built {
            self.auto_build_dashboard();
        }
        self.dock_tab = DockTab::Dashboard;
        self.dock_open = true;
        self.dashboard.stale = true;
    }

    /// Pick charts from what the columns hold: a pie for a column with a
    /// handful of values (protocol, action, status), top-value bars for
    /// hosts, addresses, ports and paths; the timestamp column is the
    /// timeline. Hashes, free text and numbers are skipped. At most six
    /// panels; the analyst adds or removes the rest.
    pub fn auto_build_dashboard(&mut self) {
        let Some(p) = &self.profile else { return };
        let mut picks: Vec<(usize, ChartKind, u8)> = Vec::new();
        for c in &p.columns {
            let (kind, priority) = match c.detected {
                SemanticType::Boolean => (ChartKind::Pie, 1),
                SemanticType::Categorical | SemanticType::HttpStatus if c.distinct <= 6 => {
                    (ChartKind::Pie, 1)
                }
                SemanticType::Categorical | SemanticType::HttpStatus if c.distinct <= 60 => {
                    (ChartKind::Bars, 3)
                }
                SemanticType::Domain | SemanticType::Url | SemanticType::Email => {
                    (ChartKind::Bars, 2)
                }
                SemanticType::Ipv4 | SemanticType::Ipv6 | SemanticType::IpPort => {
                    (ChartKind::Bars, 2)
                }
                SemanticType::Port | SemanticType::Mac => (ChartKind::Bars, 3),
                _ => continue,
            };
            picks.push((c.index, kind, priority));
        }
        picks.sort_by_key(|&(i, _, priority)| (priority, i));
        picks.truncate(6);
        picks.sort_by_key(|&(i, _, _)| i);
        for p in &self.dashboard.panels {
            if let Some(j) = &p.job {
                j.cancel.store(true, Ordering::Relaxed);
            }
        }
        self.dashboard.panels = picks
            .into_iter()
            .map(|(column, kind, _)| Panel::new(column, kind))
            .collect();
        self.dashboard.auto_built = true;
        self.dashboard.stale = true;
    }

    pub fn add_panel(&mut self, column: usize) {
        if self.dashboard.panels.iter().any(|p| p.column == column) {
            return;
        }
        let kind = match self.profile.as_ref().and_then(|p| p.column(column)) {
            Some(c)
                if c.distinct <= 6
                    && matches!(
                        c.detected,
                        SemanticType::Categorical
                            | SemanticType::HttpStatus
                            | SemanticType::Boolean
                    ) =>
            {
                ChartKind::Pie
            }
            _ => ChartKind::Bars,
        };
        self.dashboard.panels.push(Panel::new(column, kind));
        self.dashboard.stale = true;
        self.dock_tab = DockTab::Dashboard;
        self.dock_open = true;
    }

    pub fn remove_panel(&mut self, i: usize) {
        if i < self.dashboard.panels.len() {
            let p = self.dashboard.panels.remove(i);
            if let Some(j) = &p.job {
                j.cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    pub fn set_panel_kind(&mut self, i: usize, kind: ChartKind) {
        if let Some(p) = self.dashboard.panels.get_mut(i) {
            p.kind = kind;
        }
    }

    /// Identity of the selection the dashboard reflects.
    fn dashboard_key(&self) -> (usize, bool) {
        (
            self.selection
                .as_ref()
                .map_or(0, |s| Arc::as_ptr(s) as usize),
            self.search_ui.show_only,
        )
    }

    /// Recount every panel (and the timeline) over the current selection.
    fn refresh_dashboard(&mut self) {
        if !self.guard_source() {
            return;
        }
        let columns: Vec<usize> = self.dashboard.panels.iter().map(|p| p.column).collect();
        let jobs: Vec<Option<FreqJob>> = columns.iter().map(|&c| self.spawn_freq(c, 12)).collect();
        for (p, job) in self.dashboard.panels.iter_mut().zip(jobs) {
            if let Some(old) = &p.job {
                old.cancel.store(true, Ordering::Relaxed);
            }
            p.job = job;
            p.error = None;
        }
        if let Some(c) = self.timestamp_column() {
            self.start_timeline_inner(c, false);
        }
    }

    fn poll_dashboard(&mut self) {
        for p in &mut self.dashboard.panels {
            let Some(job) = &mut p.job else { continue };
            if !job.handle.as_ref().is_some_and(|h| h.is_finished()) {
                continue;
            }
            let handle = job.handle.take().expect("handle present until joined");
            let column = job.column;
            let base = job.base.as_ref().map(|n| n.count());
            p.job = None;
            match handle.join() {
                Ok(Ok(result)) if result.complete => {
                    p.view = Some(FreqView {
                        column,
                        rows: freq_rows(&result),
                        result,
                        base,
                    });
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => p.error = Some(e.to_string()),
                Err(_) => p.error = Some("count thread panicked".into()),
            }
        }
        // a new selection step (or a change of view) makes the counts stale;
        // they are recomputed when the dashboard is actually on screen
        let key = self.dashboard_key();
        if self.dashboard.key != Some(key) {
            self.dashboard.key = Some(key);
            self.dashboard.stale = true;
        }
        if self.dashboard.stale
            && self.dock_open
            && self.dock_tab == DockTab::Dashboard
            && !self.dashboard.panels.is_empty()
            && !self.source_changed
        {
            self.dashboard.stale = false;
            self.refresh_dashboard();
        }
    }

    // -- timeline ----------------------------------------------------------

    pub fn start_timeline(&mut self, column: usize) {
        if !self.guard_source() {
            return;
        }
        self.start_timeline_inner(column, true);
    }

    /// The timeline job; `switch` shows the Timeline tab (the dashboard
    /// refreshes it in place instead).
    fn start_timeline_inner(&mut self, column: usize, switch: bool) {
        if let Some(j) = &self.timeline_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        let Some(index) = self.index_snapshot() else {
            return;
        };
        let base = self.scan_base();
        let shared = Arc::new(FrequencyShared::new(self.source.len()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (source, s2, c2, b2) = (
            self.source.clone(),
            shared.clone(),
            cancel.clone(),
            base.clone(),
        );
        let handle = std::thread::Builder::new()
            .name("gridsift-timeline".into())
            .spawn(move || {
                let matches = b2.as_ref().map(|n| {
                    n.wait();
                    n.matches()
                });
                if b2.as_ref().is_some_and(|n| !n.lineage_complete()) {
                    return Err(std::io::Error::other(
                        "the selection has a cancelled or failed step",
                    ));
                }
                let selection = match &matches {
                    Some(m) => Selection::Matches(m),
                    None => Selection::All,
                };
                let opts = TimelineOptions {
                    column,
                    cancel: Some(&c2),
                    ..TimelineOptions::default()
                };
                timeline(&source, &index, selection, opts, &s2)
            })
            .expect("spawn timeline thread");
        self.timeline_job = Some(TimelineJob {
            shared,
            cancel,
            handle: Some(handle),
            column,
            base,
        });
        if switch {
            self.dock_tab = DockTab::Timeline;
            self.dock_open = true;
        }
    }

    fn poll_timeline(&mut self) {
        let Some(job) = &mut self.timeline_job else {
            return;
        };
        if !job.handle.as_ref().is_some_and(|h| h.is_finished()) {
            return;
        }
        let handle = job.handle.take().expect("handle present until joined");
        let column = job.column;
        let base = job.base.as_ref().map(|n| n.count());
        self.timeline_job = None;
        match handle.join() {
            Ok(Ok(result)) if result.complete => {
                self.timeline = Some(TimelineView::new(column, result, base))
            }
            Ok(Ok(_)) => self.status = Some("timeline cancelled".into()),
            Ok(Err(e)) => self.status = Some(format!("timeline failed: {e}")),
            Err(_) => self.status = Some("timeline thread panicked".into()),
        }
    }

    // -- enrichment --------------------------------------------------------

    /// Apply the rules assembled in the dialog: derived columns appear in
    /// the grid, in value counts and in exports.
    pub fn apply_enrichment(&mut self) {
        let rules = self.enrich_ui.rules.clone();
        if rules.is_empty() {
            self.enrichment = None;
            self.derived_names.clear();
        } else {
            let e = Enrichment::new(self.params.dialect, rules);
            self.derived_names = e.derived_names();
            self.enrichment = Some(Arc::new(e));
        }
        self.col_widths.truncate(self.header.len());
        self.col_widths.extend(
            self.derived_names
                .iter()
                .map(|n| (n.chars().count() as f32 * 7.4 + 24.0).clamp(80.0, 300.0)),
        );
        self.cache.clear();
        self.freq = None;
    }

    // -- export ------------------------------------------------------------

    /// Export the current view (the selection when filtering, else all
    /// records) plus a provenance manifest, on a background thread.
    pub fn start_export(
        &mut self,
        out: PathBuf,
        rules: Vec<RedactRule>,
        hmac_key: Option<Vec<u8>>,
        include_derived: bool,
    ) {
        self.check_source(true);
        if let Some(why) = self.export_blocker() {
            self.status = Some(format!("export not started: {why}"));
            return;
        }
        let Some(index) = self.index_snapshot() else {
            return;
        };
        // the whole output plan is checked against the evidence before
        // anything is written: the CSV, the manifest and both temporaries
        let mpath = Manifest::path_for(&out);
        for p in [&out, &mpath, &Manifest::temp_path(&mpath)] {
            if let Err(e) = self.source.guard_not_source(p) {
                self.status = Some(format!("export not started: {e}"));
                return;
            }
        }
        let node = self.scan_base();
        let matches = node.as_ref().map(|n| n.matches());
        let operations: Vec<Operation> = node.as_ref().map(|n| n.ops()).unwrap_or_default();
        let expected = matches.as_ref().map_or(index.stats.records, |m| m.len());
        let enrichment = if include_derived {
            self.enrichment.clone()
        } else {
            None
        };
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
                if let Some(e) = &enrichment {
                    operations.push(Operation::Enrich { rules: e.info() });
                }
                if let Some(r) = &redactor {
                    operations.push(Operation::Redact {
                        policy: r.policy().clone(),
                    });
                }
                let opts = ExportOptions {
                    overwrite: true,
                    redactor: redactor.as_ref(),
                    enrichment: enrichment.as_deref(),
                    cancel: Some(&c2),
                    ..ExportOptions::default()
                };
                let pending =
                    export_pending(&source, &index, selection, opts, &out2, &mut |n, _| {
                        r2.store(n, Ordering::Relaxed)
                    })
                    .map_err(|e| e.to_string())?;
                let rep = pending.report().clone();
                if !rep.complete {
                    return Ok((
                        pending.commit(None).map_err(|e| e.to_string())?,
                        PathBuf::new(),
                    ));
                }
                let out_path = std::path::absolute(&out2).unwrap_or_else(|_| out2.clone());
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
                        content: match (redactor.is_some(), enrichment.is_some()) {
                            (false, false) => "raw-records",
                            (true, false) => "records-redacted",
                            (false, true) => "records-enriched",
                            (true, true) => "records-redacted-enriched",
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
                // manifest first, then the CSV: a failure between the two
                // leaves a manifest whose digest `verify` will not match,
                // never a CSV without provenance
                let rep = pending.commit(Some(&manifest)).map_err(|e| e.to_string())?;
                let mpath = rep.manifest.clone().unwrap_or_default();
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

    /// Stop every background job (on close).
    pub fn cancel_all(&mut self) {
        if let Some(j) = &self.build {
            j.cancel.store(true, Ordering::Relaxed);
        }
        self.cancel_running_selection();
        for c in [
            self.export.as_ref().map(|j| j.cancel.clone()),
            self.freq_job.as_ref().map(|j| j.cancel.clone()),
            self.timeline_job.as_ref().map(|j| j.cancel.clone()),
            self.digest_job.as_ref().map(|j| j.cancel.clone()),
        ]
        .into_iter()
        .flatten()
        .chain(
            self.dashboard
                .panels
                .iter()
                .filter_map(|p| p.job.as_ref().map(|j| j.cancel.clone())),
        ) {
            c.store(true, Ordering::Relaxed);
        }
    }
}

/// Initial column widths from header and sample rows (character-count based).
pub fn column_widths<'a>(header: &[String], rows: impl Iterator<Item = &'a [String]>) -> Vec<f32> {
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

/// `(value, count, share)` rows of a count, ready for display.
fn freq_rows(result: &gridsift_core::frequency::FrequencyResult) -> Vec<(String, u64, f32)> {
    let total = result.counted.max(1) as f32;
    result
        .top
        .iter()
        .map(|e| {
            (
                String::from_utf8_lossy(&e.value).into_owned(),
                e.count,
                e.count as f32 / total,
            )
        })
        .collect()
}
