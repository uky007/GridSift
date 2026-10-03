//! gridsift desktop: an egui/eframe shell over `gridsift-core`.
//!
//! Layout (see `docs/design/README.md`): a title bar with the evidence
//! badges, an evidence sidebar (facts, columns, enrichment, export), a
//! command bar with the search field and the selection lineage, the grid,
//! and an analysis dock (timeline / values / profile). Every scan runs on
//! background threads; the UI thread only polls.
//!
//! The source is never written to. What this app creates on its own lives
//! in the user's cache directory (index sidecars, analysis caches); the
//! analyst's edits are saved as named version files wherever they choose,
//! and exports with their manifests where they are sent.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cache;
mod dashboard;
mod dialogs;
mod document;
mod jobs;
mod theme;
mod ui;

use std::path::{Path, PathBuf};
use std::time::Duration;

use eframe::egui::{self, Key, Modifiers};
use gridsift_core::enrich::{EnrichRule, Provider};
use gridsift_core::sidecar::versions_dir;

use crate::document::{Document, OpenOptions, RuleChoice};
use crate::ui::Action;

/// `gridsift-desktop [FILE] [--search PATTERN] [--regex] [--count COLUMN]
/// [--domain COLUMN] [--timeline] [--dashboard] [--header | --no-header]
/// [--names a,b,c]`
struct Launch {
    file: Option<PathBuf>,
    /// Read the first record as a header / as data; `None` asks the sniffer.
    header: Option<bool>,
    /// Column names for a file without a header.
    names: Option<Vec<String>>,
    search: Option<String>,
    regex: bool,
    count: Option<usize>,
    domain: Vec<usize>,
    timeline: bool,
    dashboard: bool,
    /// Smoke-test hooks: open a dialog at startup.
    export_dialog: bool,
    enrich_dialog: bool,
}

fn parse_args() -> Launch {
    let mut l = Launch {
        file: None,
        header: None,
        names: None,
        search: None,
        regex: false,
        count: None,
        domain: Vec::new(),
        timeline: false,
        dashboard: false,
        export_dialog: false,
        enrich_dialog: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--search" => l.search = args.next(),
            "--regex" => l.regex = true,
            "--filter" => {} // selections are shown filtered by default now
            "--count" => l.count = args.next().and_then(|c| c.parse().ok()),
            "--domain" => l
                .domain
                .extend(args.next().and_then(|c| c.parse::<usize>().ok())),
            "--timeline" => l.timeline = true,
            "--dashboard" => l.dashboard = true,
            "--header" => l.header = Some(true),
            "--no-header" => l.header = Some(false),
            "--names" => {
                l.names = args
                    .next()
                    .map(|s| s.split(',').map(|n| n.trim().to_string()).collect())
            }
            "--export-dialog" => l.export_dialog = true,
            "--enrich-dialog" => l.enrich_dialog = true,
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
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([760.0, 480.0])
            .with_drag_and_drop(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "gridsift",
        options,
        Box::new(move |cc| {
            // Fixed dark theme; the grid colours assume it.
            cc.egui_ctx.set_theme(egui::Theme::Dark);
            let mut app = App::default();
            if let Some(p) = &launch.file {
                let opts = OpenOptions {
                    header: launch.header,
                    names: launch.names.clone(),
                    cache_root: None,
                };
                app.open_with(&cc.egui_ctx, p, opts);
                if let Some(d) = &mut app.doc {
                    if !launch.domain.is_empty() {
                        for &c in &launch.domain {
                            d.enrich_ui.rules.push(EnrichRule {
                                column: c,
                                name: d.column_name(c),
                                provider: Provider::Domain,
                            });
                        }
                        d.apply_enrichment();
                    }
                    if let Some(pattern) = launch.search {
                        d.search_ui.pattern = pattern;
                        d.search_ui.regex = launch.regex;
                        d.start_search(&cc.egui_ctx);
                    }
                    if let Some(column) = launch.count {
                        d.start_freq(column);
                    }
                    if launch.timeline
                        && let Some(c) = d.timestamp_column()
                    {
                        d.start_timeline(c);
                    }
                    if launch.dashboard {
                        d.open_dashboard();
                    }
                    if launch.export_dialog {
                        d.export_ui.show(d.header.len());
                    }
                    if launch.enrich_dialog {
                        d.enrich_ui.open = true;
                    }
                }
            }
            Ok(Box::new(app))
        }),
    )
}

/// An action held back until the analyst decides what to do with unsaved
/// edits.
struct Confirm {
    then: Action,
    cells: usize,
    marks: usize,
}

#[derive(Default)]
struct App {
    doc: Option<Document>,
    error: Option<String>,
    confirm: Option<Confirm>,
    /// The close was confirmed (or nothing was unsaved).
    quit_ok: bool,
}

impl App {
    fn open(&mut self, ctx: &egui::Context, path: &Path) {
        self.open_with(ctx, path, OpenOptions::default());
    }

    /// Would this action throw away unsaved edits?
    fn loses_edits(&self, a: &Action) -> bool {
        matches!(
            a,
            Action::OpenDialog
                | Action::OpenPath(_)
                | Action::CloseDocument
                | Action::ToggleHeader
                | Action::SetNames(_)
                | Action::OpenVersion
                | Action::DiscardEdits
                | Action::Quit
        ) && self.doc.as_ref().is_some_and(|d| d.edits_dirty)
    }

    /// The unsaved-edits dialog: save, discard and continue, or cancel.
    fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let (cells, marks) = (c.cells, c.marks);
        let mut choice: Option<&str> = None;
        egui::Window::new("Unsaved edits")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "{cells} edited cells and {marks} marked rows are not saved in a version. \
                     They live only in this window."
                ));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save version…").clicked() {
                        choice = Some("save");
                    }
                    if ui.button("Discard and continue").clicked() {
                        choice = Some("discard");
                    }
                    if ui.button("Cancel").clicked() {
                        choice = Some("cancel");
                    }
                });
            });
        match choice {
            Some("save") => {
                if let Some(d) = &mut self.doc {
                    save_version_dialog(d);
                    if !d.edits_dirty
                        && let Some(c) = self.confirm.take()
                    {
                        self.perform(ctx, c.then);
                    }
                }
            }
            Some("discard") => {
                if let Some(c) = self.confirm.take() {
                    self.perform(ctx, c.then);
                }
            }
            Some("cancel") => self.confirm = None,
            _ => {}
        }
    }

    fn open_with(&mut self, ctx: &egui::Context, path: &Path, opts: OpenOptions) {
        self.close();
        match Document::open_with(ctx, path, opts) {
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
            d.cancel_all();
        }
        self.doc = None;
    }

    fn apply(&mut self, ctx: &egui::Context, actions: Vec<Action>) {
        for a in actions {
            // an action that would lose unsaved edits waits for the dialog
            if self.confirm.is_none() && self.loses_edits(&a) {
                let d = self.doc.as_ref().expect("dirty edits need a document");
                self.confirm = Some(Confirm {
                    then: a,
                    cells: d.edits.cells.len(),
                    marks: d.edits.marks.len(),
                });
                continue;
            }
            if self.confirm.is_some() && self.loses_edits(&a) {
                continue;
            }
            self.perform(ctx, a);
        }
    }

    fn perform(&mut self, ctx: &egui::Context, a: Action) {
        {
            match a {
                Action::OpenDialog => self.open_dialog(ctx),
                Action::OpenPath(p) => self.open(ctx, &p),
                Action::CloseDocument => self.close(),
                Action::Quit => {
                    self.quit_ok = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                // the index is keyed by the header setting, so a different
                // reading of the first record means reopening the file;
                // names describe the header-less reading and are dropped
                // when the header comes back
                Action::ToggleHeader => {
                    if let Some(d) = &self.doc {
                        let path = d.path.clone();
                        let to_header = !d.params.dialect.has_header;
                        let opts = OpenOptions {
                            header: Some(to_header),
                            names: if to_header { None } else { d.names.clone() },
                            cache_root: None,
                        };
                        self.open_with(ctx, &path, opts);
                    }
                }
                Action::NameColumns => {
                    if let Some(d) = &mut self.doc {
                        d.names_ui.text = d
                            .names
                            .clone()
                            .unwrap_or_else(|| d.header.clone())
                            .join(",");
                        d.names_ui.open = true;
                    }
                }
                Action::SetNames(names) => {
                    if let Some(d) = &self.doc {
                        let path = d.path.clone();
                        let opts = OpenOptions {
                            header: Some(false),
                            names: Some(names),
                            cache_root: None,
                        };
                        self.open_with(ctx, &path, opts);
                    }
                }
                other => {
                    if let Some(d) = &mut self.doc {
                        apply_to_document(ctx, d, other);
                    }
                }
            }
        }
    }
}

/// The save-version file picker (also used by the unsaved-edits dialog).
fn save_version_dialog(d: &mut Document) {
    let dir = versions_dir(&d.path);
    let _ = std::fs::create_dir_all(&dir);
    let stem = d
        .path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "edits".into());
    let suggested = match &d.version_path {
        Some(p) => p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        None => format!("{stem}-v1.gsedit"),
    };
    if let Some(p) = rfd::FileDialog::new()
        .set_directory(&dir)
        .set_file_name(suggested)
        .add_filter("gridsift edits", &["gsedit"])
        .save_file()
    {
        d.save_version(p);
    }
}

fn apply_to_document(ctx: &egui::Context, d: &mut Document, action: Action) {
    match action {
        Action::OpenDialog
        | Action::OpenPath(_)
        | Action::Quit
        | Action::CloseDocument
        | Action::ToggleHeader
        | Action::NameColumns
        | Action::SetNames(_) => {}
        Action::Find => {
            if !d.search_ui.pattern.is_empty() {
                d.start_search(ctx);
            }
        }
        Action::Count(c) => d.start_freq(c),
        Action::Timeline(c) => d.start_timeline(c),
        Action::SearchIn(c) => {
            d.search_ui.column = Some(c);
            d.search_ui.focus_requested = true;
        }
        Action::Enrich => {
            d.enrich_ui.open = true;
            d.enrich_ui.error = None;
        }
        Action::RedactOnExport(c) => {
            d.export_ui.show(d.header.len());
            if let Some(choice) = d.export_ui.choices.get_mut(c)
                && *choice == RuleChoice::Keep
            {
                *choice = RuleChoice::Mask;
            }
        }
        Action::Export => d.export_ui.show(d.header.len()),
        Action::RevertTo(node) => d.revert_to(node),
        Action::PopSelection => d.pop_selection(),
        Action::ClearSelection => d.clear_selection(),
        // a value from the counts table selects exactly that value, so the
        // click yields the count that was shown
        Action::Pivot(column, value) => {
            d.search_ui.pattern = value;
            d.search_ui.column = Some(column);
            d.search_ui.regex = false;
            d.search_ui.exact = true;
            d.search_ui.ignore_case = false;
            d.search_ui.invert = false;
            d.search_ui.show_only = true;
            d.start_search(ctx);
        }
        Action::FilterRange(column, from, to) => d.start_time_range(ctx, column, from, to),
        Action::Dashboard => d.open_dashboard(),
        Action::AutoBuild => {
            d.auto_build_dashboard();
            d.open_dashboard();
        }
        Action::AddPanel(c) => d.add_panel(c),
        Action::RemovePanel(i) => d.remove_panel(i),
        Action::PanelKind(i, kind) => d.set_panel_kind(i, kind),
        // versions live wherever the analyst puts them; the data directory
        // is offered, never the evidence folder
        Action::SaveVersion => save_version_dialog(d),
        // reached only after the unsaved-edits dialog, if there were any
        Action::OpenVersion => {
            let dir = versions_dir(&d.path);
            let _ = std::fs::create_dir_all(&dir);
            if let Some(p) = rfd::FileDialog::new()
                .set_directory(&dir)
                .add_filter("gridsift edits", &["gsedit"])
                .pick_file()
            {
                d.load_version(p, true);
            }
        }
        Action::DiscardEdits => d.discard_edits(),
        Action::GoTo(r) => {
            let max = d.known_rows.saturating_sub(1);
            d.pending_scroll = Some(r.min(max));
        }
    }
}

impl eframe::App for App {
    /// Scroll offsets and widget state must not leak from one evidence file
    /// (or session) to the next.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // drag & drop, shortcuts
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        let mut early = Vec::new();
        if let Some(p) = dropped.first() {
            early.push(Action::OpenPath(p.clone()));
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            early.push(Action::OpenDialog);
        }
        // closing the window with unsaved edits asks first
        if ctx.input(|i| i.viewport().close_requested())
            && !self.quit_ok
            && self.doc.as_ref().is_some_and(|d| d.edits_dirty)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            early.push(Action::Quit);
        }
        if !early.is_empty() {
            self.apply(ctx, early);
        }
        if let Some(d) = &mut self.doc {
            d.poll_all();
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
                d.search_ui.focus_requested = true;
            }
        }

        let mut actions = ui::title_bar(ctx, self.doc.as_ref());
        ui::status_bar(ctx, self.doc.as_ref(), self.error.as_ref());
        match &mut self.doc {
            Some(d) => {
                actions.extend(ui::sidebar(ctx, d));
                actions.extend(ui::command_bar(ctx, d));
                actions.extend(ui::dock(ctx, d));
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE.inner_margin(0.0))
                    .show(ctx, |ui| ui::grid(ui, d));
                dialogs::export_window(ctx, d);
                dialogs::enrich_window(ctx, d);
                if let Some(names) = dialogs::names_window(ctx, d) {
                    actions.push(Action::SetNames(names));
                }
            }
            None => {
                egui::CentralPanel::default().show(ctx, ui::empty_state);
            }
        }
        self.apply(ctx, actions);
        self.confirm_window(ctx);

        // keep progress displays moving while background work runs
        if self.doc.as_ref().is_some_and(Document::busy) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
