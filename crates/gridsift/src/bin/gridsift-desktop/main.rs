//! gridsift desktop: an egui/eframe shell over `gridsift-core`.
//!
//! Layout (see `docs/design/README.md`): a title bar with the evidence
//! badges, an evidence sidebar (facts, columns, enrichment, export), a
//! command bar with the search field and the selection lineage, the grid,
//! and an analysis dock (timeline / values / profile). Every scan runs on
//! background threads; the UI thread only polls.
//!
//! The source is never written to; the only file this app creates is the
//! index sidecar in the user's cache directory.

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

#[derive(Default)]
struct App {
    doc: Option<Document>,
    error: Option<String>,
}

impl App {
    fn open(&mut self, ctx: &egui::Context, path: &Path) {
        self.open_with(ctx, path, OpenOptions::default());
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
            match a {
                Action::OpenDialog => self.open_dialog(ctx),
                Action::CloseDocument => self.close(),
                // the index is keyed by the header setting, so a different
                // reading of the first record means reopening the file
                Action::ToggleHeader => {
                    if let Some(d) = &self.doc {
                        let path = d.path.clone();
                        let opts = OpenOptions {
                            header: Some(!d.params.dialect.has_header),
                            names: d.names.clone(),
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

fn apply_to_document(ctx: &egui::Context, d: &mut Document, action: Action) {
    match action {
        Action::OpenDialog
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
        if let Some(p) = dropped.first() {
            self.open(ctx, p);
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.open_dialog(ctx);
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

        // keep progress displays moving while background work runs
        if self.doc.as_ref().is_some_and(Document::busy) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
