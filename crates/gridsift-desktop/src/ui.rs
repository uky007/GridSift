//! The panels of the main window. Panels only draw and collect [`Action`]s;
//! the app applies them after the frame so borrows stay simple.

use std::sync::Arc;

use eframe::egui::{self, Align, Key, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Bar, BarChart, Plot, PlotPoints, Polygon};
use gridsift_core::enrich::Provider;
use gridsift_core::hash::hex;
use gridsift_core::sys::{group_thousands, human_bytes, iso8601_utc, peak_rss_bytes};

use crate::document::{DockTab, Document};
use crate::jobs::{ChartKind, SelectionNode, SelectionState, TimelineView};
use crate::theme::{
    self, AMBER, BLUE, CELL_TEXT, DIM, GREEN, HEADER_HEIGHT, HEADER_TEXT, KHAKI, RED, ROW_HEIGHT,
    ROW_NUMBER_TEXT, TEAL,
};

/// Rows fetched around a cache miss (biased forward: scrolling down is common).
const FETCH_BEFORE: u64 = 64;
const FETCH_TOTAL: usize = 512;
/// Matches fetched per cache miss in the filtered view.
const FETCH_FILTERED: u64 = 96;

/// Something the analyst asked for, applied by the app after drawing.
pub enum Action {
    OpenDialog,
    CloseDocument,
    Find,
    Count(usize),
    Timeline(usize),
    SearchIn(usize),
    Enrich,
    RedactOnExport(usize),
    Export,
    RevertTo(Arc<SelectionNode>),
    PopSelection,
    ClearSelection,
    /// Filter to `column == value` (a click in the values tab).
    Pivot(usize, String),
    /// Filter to a time range of `column`.
    FilterRange(usize, i64, i64),
    GoTo(u64),
    /// Show the dashboard (built from the profile the first time).
    Dashboard,
    /// Rebuild the dashboard from the column profile.
    AutoBuild,
    AddPanel(usize),
    RemovePanel(usize),
    PanelKind(usize, ChartKind),
}

// ---------------------------------------------------------------------------
// title bar

pub fn title_bar(ctx: &egui::Context, doc: Option<&Document>) -> Vec<Action> {
    let mut actions = Vec::new();
    egui::TopBottomPanel::top("title")
        .frame(
            egui::Frame::NONE
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(12, 6)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("gridsift").strong());
                if let Some(d) = doc {
                    ui.add_space(6.0);
                    ui.label(
                        d.path
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    );
                    ui.label(RichText::new(human_bytes(d.source.len())).color(DIM));
                    ui.add_space(6.0);
                    theme::badge(ui, "EVIDENCE · READ ONLY", TEAL);
                    theme::badge(ui, "STRICT OFFLINE", BLUE);
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.menu_button("☰", |ui| {
                        if ui.button(format!("Open…    {}O", theme::CMD)).clicked() {
                            actions.push(Action::OpenDialog);
                            ui.close();
                        }
                        if doc.is_some() && ui.button("Close").clicked() {
                            actions.push(Action::CloseDocument);
                            ui.close();
                        }
                        ui.separator();
                        ui.label(
                            RichText::new(format!("gridsift {}", env!("CARGO_PKG_VERSION"))).weak(),
                        );
                    });
                });
            });
        });
    actions
}

// ---------------------------------------------------------------------------
// evidence sidebar

pub fn sidebar(ctx: &egui::Context, d: &mut Document) -> Vec<Action> {
    let mut actions = Vec::new();
    egui::SidePanel::left("evidence")
        .resizable(true)
        .default_width(250.0)
        .width_range(200.0..=420.0)
        .frame(
            egui::Frame::NONE
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(12, 6)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("sidebar-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    evidence_section(ui, d);
                    columns_section(ui, d, &mut actions);
                    enrichment_section(ui, d, &mut actions);
                    ui.add_space(12.0);
                    let blocker = d.export_blocker();
                    let r = ui.add_enabled(
                        blocker.is_none(),
                        egui::Button::new(RichText::new("Export finding…").color(AMBER)),
                    );
                    if r.on_disabled_hover_text(blocker.unwrap_or_default())
                        .clicked()
                    {
                        actions.push(Action::Export);
                    }
                    ui.add_space(8.0);
                });
        });
    actions
}

fn evidence_section(ui: &mut egui::Ui, d: &Document) {
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
    theme::section(ui, "EVIDENCE");
    if d.source_changed {
        egui::Frame::NONE
            .fill(egui::Color32::from_rgb(0x5a, 0x1e, 0x1e))
            .corner_radius(4.0)
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.label(RichText::new("SOURCE CHANGED ON DISK").strong().color(RED));
                ui.label(
                    RichText::new(
                        "size or modification time differ from when the file was opened; \
                         the digest, index and selection below are stale — reopen the file",
                    )
                    .size(11.5)
                    .color(RED),
                );
            });
        ui.add_space(4.0);
    }
    egui::Grid::new("evidence-facts")
        .num_columns(2)
        .spacing([8.0, 3.0])
        .show(ui, |ui| {
            let shown = if complete {
                records
            } else {
                d.known_rows.max(records)
            };
            theme::fact(ui, "Records", RichText::new(group_thousands(shown)));
            match &sha {
                Some(h) => theme::fact(
                    ui,
                    "SHA-256",
                    RichText::new(format!("{}… ✔", &h[..16])).color(GREEN),
                ),
                None => {
                    let pct = d.build.as_ref().map_or(0.0, |j| j.fraction() * 100.0);
                    theme::fact(
                        ui,
                        "SHA-256",
                        RichText::new(format!("computing {pct:.0}%")).color(DIM),
                    );
                }
            }
            let index_text = match (&d.build, d.index_elapsed, d.index_from_sidecar) {
                (Some(j), _, _) => {
                    RichText::new(format!("building {:.0}%", j.fraction() * 100.0)).color(AMBER)
                }
                (None, Some(t), _) => {
                    RichText::new(format!("complete · {:.2} s", t.as_secs_f64())).color(GREEN)
                }
                (None, None, true) => RichText::new("complete · from cache").color(GREEN),
                (None, None, false) if complete => RichText::new("complete").color(GREEN),
                (None, None, false) => RichText::new("partial").color(KHAKI),
            };
            theme::fact(ui, "Index", index_text);
            let dl = d.params.dialect;
            theme::fact(
                ui,
                "Dialect",
                RichText::new(format!(
                    "{:?} {} {}",
                    dl.delimiter as char,
                    dl.quote
                        .map_or("no-quote".to_string(), |q| format!("{:?}", q as char)),
                    if dl.has_header { "header" } else { "no header" }
                )),
            );
            let cols = if d.derived_names.is_empty() {
                format!("{}", d.header.len())
            } else {
                format!("{} + {} derived", d.header.len(), d.derived_names.len())
            };
            theme::fact(ui, "Columns", RichText::new(cols));
            let bad = mismatches + lenient + unterminated;
            theme::fact(
                ui,
                "Malformed",
                if bad == 0 {
                    RichText::new("0")
                } else {
                    RichText::new(format!(
                        "{mismatches} fields · {lenient} quotes · {unterminated} open"
                    ))
                    .color(KHAKI)
                },
            );
        });
    if let Some(job) = &d.build {
        let (rate, eta) = job.rate_and_eta();
        ui.add(
            egui::ProgressBar::new(job.fraction())
                .desired_width(ui.available_width())
                .text(format!("{}/s · eta {:.0} s", human_bytes(rate as u64), eta)),
        );
        if ui.small_button("Cancel indexing").clicked() {
            job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    if let Some(e) = &d.build_error {
        ui.colored_label(RED, format!("indexing failed: {e}"));
    }
}

fn columns_section(ui: &mut egui::Ui, d: &Document, actions: &mut Vec<Action>) {
    theme::section(ui, "COLUMNS");
    let n_source = d.header.len();
    for i in 0..d.column_count() {
        let name = d.column_name(i);
        let derived = i >= n_source;
        let typed = if derived {
            "derived".to_string()
        } else {
            d.profile
                .as_ref()
                .and_then(|p| p.column(i))
                .map(|c| format!("{} {:.0}%", c.detected.name(), c.confidence * 100.0))
                .unwrap_or_default()
        };
        let color = if derived { GREEN } else { HEADER_TEXT };
        let type_color = if derived { GREEN } else { AMBER };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.menu_button(
                RichText::new(&name).monospace().size(12.0).color(color),
                |ui| {
                    ui.set_min_width(180.0);
                    if ui.button("Count values").clicked() {
                        actions.push(Action::Count(i));
                        ui.close();
                    }
                    if ui.button("Add to dashboard").clicked() {
                        actions.push(Action::AddPanel(i));
                        ui.close();
                    }
                    if !derived {
                        if ui.button("Timeline").clicked() {
                            actions.push(Action::Timeline(i));
                            ui.close();
                        }
                        if ui.button("Search in this column").clicked() {
                            actions.push(Action::SearchIn(i));
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Enrich…").clicked() {
                            actions.push(Action::Enrich);
                            ui.close();
                        }
                        if ui.button("Redact on export…").clicked() {
                            actions.push(Action::RedactOnExport(i));
                            ui.close();
                        }
                    }
                },
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(typed).size(10.5).color(type_color));
            });
        });
    }
}

fn enrichment_section(ui: &mut egui::Ui, d: &Document, actions: &mut Vec<Action>) {
    theme::section(ui, "ENRICHMENT");
    match &d.enrichment {
        Some(e) => {
            for r in e.rules() {
                let dataset = match &r.provider {
                    Provider::GeoIp(p) => p.info().name.clone(),
                    Provider::Lookup(t) => t.info().name.clone(),
                    Provider::Domain => "public suffix list".into(),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&r.name).monospace().size(12.0));
                    ui.label(RichText::new("→").monospace().color(DIM));
                    ui.label(RichText::new(dataset).monospace().size(12.0).color(GREEN));
                });
            }
        }
        None => {
            ui.label(RichText::new("none").color(DIM));
        }
    }
    if ui.small_button("+ add / edit").clicked() {
        actions.push(Action::Enrich);
    }
}

// ---------------------------------------------------------------------------
// command bar: search and the selection lineage

pub fn command_bar(ctx: &egui::Context, d: &mut Document) -> Vec<Action> {
    let mut actions = Vec::new();
    egui::TopBottomPanel::top("command")
        .frame(
            egui::Frame::NONE
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(12, 8)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔍").color(DIM));
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut d.search_ui.pattern)
                        .desired_width(420.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text(format!("literal text, or a regex  ({}F)", theme::CMD)),
                );
                if d.search_ui.focus_requested {
                    resp.request_focus();
                    d.search_ui.focus_requested = false;
                }
                if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    actions.push(Action::Find);
                }
                // Regex and Exact are alternatives; the last one switched on wins
                if theme::toggle_chip(ui, &mut d.search_ui.regex, "Regex") && d.search_ui.regex {
                    d.search_ui.exact = false;
                }
                if theme::toggle_chip(ui, &mut d.search_ui.exact, "Exact") && d.search_ui.exact {
                    d.search_ui.regex = false;
                }
                theme::toggle_chip(ui, &mut d.search_ui.ignore_case, "Aa");
                theme::toggle_chip(ui, &mut d.search_ui.invert, "Invert");
                let col_label = match d.search_ui.column {
                    None => "all columns".to_string(),
                    Some(c) => d.column_name(c),
                };
                egui::ComboBox::from_id_salt("search-column")
                    .selected_text(col_label)
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut d.search_ui.column, None, "all columns");
                        for (i, name) in d.header.iter().enumerate() {
                            ui.selectable_value(&mut d.search_ui.column, Some(i), name);
                        }
                    });
                if ui.button("Find").clicked() {
                    actions.push(Action::Find);
                }
                if let Some(e) = &d.search_ui.error {
                    ui.colored_label(RED, format!("invalid pattern: {e}"));
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new("Go to row").color(DIM));
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut d.goto)
                            .desired_width(90.0)
                            .hint_text("0-based"),
                    );
                    if r.lost_focus()
                        && ui.input(|i| i.key_pressed(Key::Enter))
                        && let Ok(n) = d.goto.replace([',', '_'], "").trim().parse::<u64>()
                    {
                        actions.push(Action::GoTo(n));
                    }
                });
            });

            let Some(sel) = d.selection.clone() else {
                return;
            };
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let chain = sel.lineage();
                let last = chain.len() - 1;
                for (k, node) in chain.iter().enumerate() {
                    if k > 0 {
                        ui.label(RichText::new("▶").size(9.0).color(DIM));
                    }
                    let is_current = k == last;
                    let state = node.state();
                    let count = format!("{}{}", group_thousands(node.count()), state.label());
                    let text = format!("{}  {count}", node.op.describe(&d.header));
                    // a cancelled or failed step holds a partial result:
                    // khaki, and nothing downstream will use it
                    let color = match state {
                        SelectionState::Cancelled | SelectionState::Failed(_) => KHAKI,
                        _ if is_current => AMBER,
                        _ => DIM,
                    };
                    let (clicked, closed) = theme::chip(ui, &text, color, is_current);
                    if clicked && !is_current {
                        actions.push(Action::RevertTo(node.clone()));
                    }
                    if closed {
                        actions.push(Action::PopSelection);
                    }
                }
                ui.add_space(8.0);
                if sel.running() {
                    ui.add(egui::ProgressBar::new(sel.shared.fraction()).desired_width(120.0));
                    if ui.small_button("Cancel").clicked() {
                        sel.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    ui.label(RichText::new(sel.status_line()).color(DIM).size(11.5));
                }
                ui.add_space(8.0);
                theme::toggle_chip(ui, &mut d.search_ui.show_only, "show only matches");
                if !d.search_ui.show_only && !sel.running() {
                    let m = sel.shared.matches.lock().expect("match set");
                    if ui.small_button("◀ prev").clicked() {
                        match m.prev_before(d.first_visible) {
                            Some(r) => actions.push(Action::GoTo(r)),
                            None => d.status = Some("no earlier match".into()),
                        }
                    }
                    if ui.small_button("next ▶").clicked() {
                        match m.next_after(d.first_visible) {
                            Some(r) => actions.push(Action::GoTo(r)),
                            None => d.status = Some("no further match".into()),
                        }
                    }
                }
                if ui.small_button("clear").clicked() {
                    actions.push(Action::ClearSelection);
                }
            });
        });
    actions
}

// ---------------------------------------------------------------------------
// grid

pub fn grid(ui: &mut egui::Ui, d: &mut Document) {
    let filter = d.filtering();
    let Document {
        source,
        index,
        cache,
        col_widths,
        header,
        pending_scroll,
        first_visible,
        selection,
        known_rows,
        profile,
        path,
        enrichment,
        derived_names,
        ..
    } = d;
    let enrichment = enrichment.as_deref();
    let idx = index.read().expect("index lock");
    // Hold the match set for the frame: `select`/`contains` per visible row.
    let matches = selection
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
                let (name, is_derived) = match header.get(c) {
                    Some(n) => (n.as_str(), false),
                    None => (
                        c.checked_sub(header.len())
                            .and_then(|k| derived_names.get(k))
                            .map_or("", String::as_str),
                        true,
                    ),
                };
                let typed = if is_derived {
                    Some("derived".to_string())
                } else {
                    profile
                        .as_ref()
                        .and_then(|p| p.column(c))
                        .map(|cp| format!("{} {:.0}%", cp.detected.name(), cp.confidence * 100.0))
                };
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.add(
                        egui::Label::new(RichText::new(name).strong().color(if is_derived {
                            GREEN
                        } else {
                            HEADER_TEXT
                        }))
                        .truncate(),
                    );
                    let typed = typed.as_deref().unwrap_or("");
                    ui.add(
                        egui::Label::new(RichText::new(typed).small().color(if is_derived {
                            GREEN
                        } else {
                            AMBER
                        }))
                        .truncate(),
                    );
                });
            });
        }
    })
    .body(|body| {
        body.rows(ROW_HEIGHT, total, |mut row| {
            let k = row.index() as u64;
            // amber row numbers mark matches in the highlight view only;
            // in the filtered view every row is one
            let (r, is_match) = match (&matches, filter) {
                (Some(m), true) => (m.select(k).unwrap_or(k), false),
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
                        cache.fill_many(source, &idx, enrichment, &ords);
                    }
                    _ => {
                        cache.fill_window(
                            source,
                            &idx,
                            enrichment,
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
                        .color(if is_match { AMBER } else { ROW_NUMBER_TEXT }),
                );
            });
            let fields = cache.get(r);
            for c in 0..ncols {
                row.col(|ui| {
                    let text = fields.and_then(|f| f.get(c)).map_or("", String::as_str);
                    let color = if c >= header.len() { GREEN } else { CELL_TEXT };
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace().color(color)).truncate(),
                    );
                });
            }
        });
    });
    if let Some(t) = top {
        *first_visible = t;
    }
}

fn row_number_width(total: usize) -> f32 {
    let digits = group_thousands(total.max(1) as u64).len();
    (digits as f32 * 8.0 + 14.0).max(40.0)
}

// ---------------------------------------------------------------------------
// analysis dock

pub fn dock(ctx: &egui::Context, d: &mut Document) -> Vec<Action> {
    let mut actions = Vec::new();
    if !d.dock_open {
        return actions;
    }
    // one panel id per tab, so the dashboard opens tall and the tables
    // keep their own height
    let (id, default_height) = match d.dock_tab {
        DockTab::Dashboard => ("dock-dashboard", 668.0),
        _ => ("dock", 260.0),
    };
    egui::TopBottomPanel::bottom(id)
        .resizable(true)
        .default_height(default_height)
        .frame(
            egui::Frame::NONE
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(12, 6)),
        )
        .show(ctx, |ui| {
            let mut close = false;
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (DockTab::Dashboard, "Dashboard"),
                    (DockTab::Timeline, "Timeline"),
                    (DockTab::Values, "Values"),
                    (DockTab::Profile, "Profile"),
                ] {
                    if ui.selectable_label(d.dock_tab == tab, label).clicked() {
                        if tab == DockTab::Dashboard {
                            actions.push(Action::Dashboard);
                        }
                        d.dock_tab = tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("✖").clicked() {
                        close = true;
                    }
                });
            });
            ui.separator();
            match d.dock_tab {
                DockTab::Dashboard => crate::dashboard::dashboard_tab(ui, d, &mut actions),
                DockTab::Timeline => timeline_tab(ui, d, &mut actions),
                DockTab::Values => values_tab(ui, d, &mut actions),
                DockTab::Profile => profile_tab(ui, d),
            }
            if close {
                d.dock_open = false;
            }
        });
    actions
}

/// "within the selection" / "all records" for an analysis result.
fn scope_label(ui: &mut egui::Ui, base: Option<u64>) {
    match base {
        Some(n) => {
            ui.label(
                RichText::new(format!("within selection ({} records)", group_thousands(n)))
                    .color(AMBER),
            );
        }
        None => {
            ui.label(RichText::new("all records").color(DIM));
        }
    }
}

/// Axis / tooltip label for a Unix-seconds x value.
pub(crate) fn time_label(secs: f64, width: i64) -> String {
    if secs < 0.0 {
        return format!("{secs:.0}");
    }
    let iso = iso8601_utc(secs as u64);
    if width >= 86_400 {
        iso[..10].to_string()
    } else {
        format!("{} {}", &iso[5..10], &iso[11..16])
    }
}

pub(crate) fn human_width(secs: i64) -> String {
    match secs {
        s if s % 604_800 == 0 => format!("{}w", s / 604_800),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn timeline_tab(ui: &mut egui::Ui, d: &mut Document, actions: &mut Vec<Action>) {
    let mut new_width: Option<Option<i64>> = None;
    ui.horizontal(|ui| {
        if let Some(job) = &d.timeline_job {
            ui.label(format!("timeline of {}…", d.column_name(job.column)));
            ui.add(egui::ProgressBar::new(job.shared.fraction()).desired_width(160.0));
            if ui.small_button("Cancel").clicked() {
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
        let Some(v) = &d.timeline else {
            ui.label(
                RichText::new("no timeline yet — pick a timestamp column in the sidebar")
                    .color(DIM),
            );
            if let Some(c) = d.timestamp_column()
                && ui
                    .small_button(format!("Timeline of {}", d.column_name(c)))
                    .clicked()
            {
                actions.push(Action::Timeline(c));
            }
            return;
        };
        let r = &v.result;
        ui.label(RichText::new(d.column_name(v.column)).monospace().strong());
        ui.label(
            RichText::new(format!(
                "{} parsed · {} unparseable · {} … {} · {:.2} s",
                group_thousands(r.parsed),
                group_thousands(r.unparsed),
                r.min.map_or("-".into(), |t| time_label(t as f64, 1)),
                r.max.map_or("-".into(), |t| time_label(t as f64, 1)),
                r.elapsed.as_secs_f64()
            ))
            .color(DIM),
        );
        scope_label(ui, v.base);
        ui.separator();
        ui.label(RichText::new("bucket").color(DIM));
        let current = if v.auto {
            format!("auto ({})", human_width(v.width))
        } else {
            human_width(v.width)
        };
        egui::ComboBox::from_id_salt("timeline-width")
            .selected_text(current)
            .width(110.0)
            .show_ui(ui, |ui| {
                if ui.selectable_label(v.auto, "auto").clicked() {
                    new_width = Some(None);
                }
                for w in [60i64, 300, 900, 3600, 21_600, 86_400, 604_800] {
                    if w >= r.resolution
                        && ui
                            .selectable_label(!v.auto && v.width == w, human_width(w))
                            .clicked()
                    {
                        new_width = Some(Some(w));
                    }
                }
            });
        if let Some((from, to)) = v.snapped() {
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "selected {} – {}",
                    time_label(from as f64, 1),
                    time_label(to as f64, 1)
                ))
                .color(GREEN),
            );
            if ui
                .button(RichText::new("Filter to range").color(AMBER))
                .clicked()
            {
                actions.push(Action::FilterRange(v.column, from, to));
            }
        } else {
            ui.label(RichText::new("drag on the chart to select a range").color(DIM));
        }
    });
    if let (Some(v), Some(w)) = (&mut d.timeline, new_width) {
        v.set_width(w);
    }
    let Some(v) = &mut d.timeline else { return };
    if d.timeline_job.is_some() {
        return;
    }
    let height = ui.available_height().max(100.0);
    timeline_plot(ui, v, "timeline-plot", height);
}

/// The bucketed bar chart with drag-to-select; shared by the Timeline tab
/// and the dashboard's timeline card.
pub(crate) fn timeline_plot(ui: &mut egui::Ui, v: &mut TimelineView, id: &str, height: f32) {
    let width = v.width as f64;
    let ymax = v.bars.iter().map(|b| b.1).max().unwrap_or(1).max(1) as f64;
    let bars: Vec<Bar> = v
        .bars
        .iter()
        .map(|&(s, c)| Bar::new(s as f64 + width / 2.0, c as f64).width(width * 0.9))
        .collect();
    let w = v.width;
    Plot::new(id)
        .height(height)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .allow_boxed_zoom(false)
        .include_y(0.0)
        .x_axis_formatter(move |mark, _| time_label(mark.value, w))
        .label_formatter(move |_, p| format!("{}\n{:.0}", time_label(p.x, w), p.y))
        .show(ui, |pui| {
            pui.bar_chart(BarChart::new("events", bars).color(AMBER));
            if let Some((a, b)) = v.sel {
                pui.polygon(
                    Polygon::new(
                        "selection",
                        PlotPoints::from(vec![[a, 0.0], [b, 0.0], [b, ymax], [a, ymax]]),
                    )
                    .fill_color(egui::Color32::from_rgba_unmultiplied(120, 200, 140, 70))
                    .stroke(egui::Stroke::new(1.0_f32, GREEN)),
                );
            }
            let resp = pui.response().clone();
            let pointer = pui.pointer_coordinate();
            if resp.drag_started() {
                v.drag_from = pointer.map(|p| p.x);
            }
            if resp.dragged()
                && let (Some(f), Some(p)) = (v.drag_from, pointer)
            {
                v.sel = Some((f.min(p.x), f.max(p.x)));
            }
            if resp.clicked()
                && let Some(p) = pointer
            {
                let s = (p.x / width).floor() * width;
                v.sel = Some((s, s + width));
            }
        });
}

fn values_tab(ui: &mut egui::Ui, d: &mut Document, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        if let Some(job) = &d.freq_job {
            ui.label(format!("counting {}…", d.column_name(job.column)));
            ui.add(egui::ProgressBar::new(job.shared.fraction()).desired_width(160.0));
            if ui.small_button("Cancel").clicked() {
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
        let Some(v) = &d.freq else {
            ui.label(
                RichText::new(
                    "no counts yet — pick a column in the sidebar and choose Count values",
                )
                .color(DIM),
            );
            return;
        };
        let r = &v.result;
        ui.label(RichText::new(d.column_name(v.column)).monospace().strong());
        if v.column >= d.header.len() {
            ui.label(RichText::new("(derived)").color(GREEN));
        }
        ui.label(
            RichText::new(format!(
                "{} distinct{} · {} records · {} empty · {:.2} s",
                group_thousands(r.distinct),
                if r.exact { "" } else { " (estimated)" },
                group_thousands(r.counted),
                group_thousands(r.empty),
                r.elapsed.as_secs_f64()
            ))
            .color(DIM),
        );
        scope_label(ui, v.base);
        if !r.exact {
            ui.label(
                RichText::new(format!(
                    "counts may be under by up to {}",
                    group_thousands(r.error_bound)
                ))
                .color(KHAKI),
            );
        }
        if v.column < d.header.len() {
            ui.label(RichText::new("click a value to filter by it").color(DIM));
        }
    });
    if d.freq_job.is_some() {
        return;
    }
    let Some(v) = &d.freq else { return };
    let pivotable = v.column < d.header.len();
    // bars are relative to the top value, not the record count
    let top_share = v.rows.first().map_or(1.0, |r| r.2).max(f32::EPSILON);
    let mut clicked: Option<(usize, String)> = None;
    TableBuilder::new(ui)
        .id_salt("freq-table")
        .striped(true)
        .sense(Sense::click())
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
                        egui::Label::new(RichText::new(value).monospace().color(CELL_TEXT))
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
                        theme::Bar::new(*share / top_share)
                            .desired_width(ui.available_width().max(40.0)),
                    );
                });
                if pivotable && row.response().clicked() {
                    clicked = Some((v.column, value.clone()));
                }
            });
        });
    if let Some((c, value)) = clicked {
        actions.push(Action::Pivot(c, value));
    }
}

fn profile_tab(ui: &mut egui::Ui, d: &Document) {
    let Some(p) = &d.profile else {
        ui.label(RichText::new("profiling…").color(DIM));
        return;
    };
    ui.label(
        RichText::new(format!(
            "sampled {} rows{}",
            group_thousands(p.sampled_records),
            if p.spans_file {
                " across the file"
            } else {
                " from the head only (file-wide once indexed)"
            }
        ))
        .color(DIM),
    );
    TableBuilder::new(ui)
        .id_salt("profile-table")
        .striped(true)
        .vscroll(true)
        .auto_shrink([false, false])
        .cell_layout(egui::Layout::left_to_right(Align::Center))
        .column(Column::initial(180.0).at_least(60.0).clip(true))
        .column(Column::exact(110.0))
        .column(Column::exact(60.0))
        .column(Column::exact(90.0))
        .column(Column::exact(70.0))
        .column(Column::remainder().clip(true))
        .header(20.0, |mut h| {
            for t in ["column", "type", "conf", "distinct", "max len", "examples"] {
                h.col(|ui| {
                    ui.label(RichText::new(t).strong().color(HEADER_TEXT));
                });
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, p.columns.len(), |mut row| {
                let c = &p.columns[row.index()];
                let cell = |ui: &mut egui::Ui, s: String, color| {
                    ui.add(egui::Label::new(RichText::new(s).monospace().color(color)).truncate());
                };
                row.col(|ui| cell(ui, c.name.clone(), CELL_TEXT));
                row.col(|ui| cell(ui, c.detected.name().to_string(), AMBER));
                row.col(|ui| cell(ui, format!("{:.0}%", c.confidence * 100.0), CELL_TEXT));
                row.col(|ui| cell(ui, group_thousands(c.distinct as u64), CELL_TEXT));
                row.col(|ui| cell(ui, c.max_len.to_string(), CELL_TEXT));
                row.col(|ui| {
                    let ex = c
                        .examples
                        .iter()
                        .map(|e| e.replace('\n', "\\n"))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    cell(ui, ex, DIM);
                });
            });
        });
}

// ---------------------------------------------------------------------------
// status bar and empty state

pub fn status_bar(ctx: &egui::Context, doc: Option<&Document>, error: Option<&String>) {
    egui::TopBottomPanel::bottom("status")
        .frame(
            egui::Frame::NONE
                .fill(theme::PANEL)
                .inner_margin(egui::Margin::symmetric(12, 4)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(e) = error {
                    ui.colored_label(RED, e);
                } else if let Some(d) = doc {
                    if let Some(s) = &d.status {
                        ui.label(RichText::new(s).monospace().size(11.5).color(KHAKI));
                    } else {
                        ui.label(
                            RichText::new(format!(
                                "first rows in {:.1} ms",
                                d.first_rows_in.as_secs_f64() * 1000.0
                            ))
                            .color(DIM),
                        );
                        if let Some(t) = d.index_elapsed {
                            ui.separator();
                            ui.label(
                                RichText::new(format!("index {:.2} s", t.as_secs_f64())).color(DIM),
                            );
                        } else if d.index_from_sidecar {
                            ui.separator();
                            ui.label(RichText::new("index from cache").color(DIM));
                        }
                        ui.separator();
                        ui.label(
                            RichText::new(format!(
                                "{} rows cached",
                                group_thousands(d.cache.len() as u64)
                            ))
                            .color(DIM),
                        );
                    }
                } else {
                    ui.label(
                        RichText::new(format!(
                            "Drop a CSV/TSV file here, or press {}O",
                            theme::CMD
                        ))
                        .color(DIM),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("peak RSS {}", human_bytes(peak_rss_bytes())))
                            .color(DIM),
                    );
                    if doc.is_some_and(Document::busy) {
                        ui.spinner();
                    }
                });
            });
        });
}

pub fn empty_state(ui: &mut egui::Ui) {
    ui.centered_and_justified(|ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.35);
            ui.label(RichText::new(format!("Drop a CSV / TSV file here, or press {}O", theme::CMD)).size(22.0).color(DIM));
            ui.add_space(14.0);
            ui.label(RichText::new("never modified  ·  never uploaded  ·  never resolved").size(14.0).color(DIM));
            ui.add_space(6.0);
            ui.label(
                RichText::new("The file is opened read-only and hashed; every derived artefact carries a provenance manifest.")
                    .size(12.0)
                    .color(DIM),
            );
        });
    });
}
