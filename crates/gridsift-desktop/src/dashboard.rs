//! The Dashboard tab: charts picked from what the columns hold, following
//! the current selection, each click a new selection step.
//!
//! Charts are painted directly (no plot widget) so that a slice or a bar
//! is a thing the analyst can hover and click; the timeline reuses the
//! plot from the Timeline tab.

use std::f32::consts::{PI, TAU};

use eframe::egui::{self, Align, Color32, Pos2, Rect, RichText, Sense, Stroke, Vec2};
use gridsift_core::sys::group_thousands;

use crate::document::Document;
use crate::jobs::{ChartKind, Panel};
use crate::theme::{AMBER, CELL_TEXT, DIM, GREEN, KHAKI, PALETTE, RED};
use crate::ui::{Action, timeline_plot};

const CARD_HEIGHT: f32 = 236.0;
const CARD_MIN_WIDTH: f32 = 300.0;
const PIE_SIZE: f32 = 150.0;
/// Slices drawn individually; the rest is "other".
const PIE_SLICES: usize = 7;
const BAR_ROWS: usize = 10;

pub fn dashboard_tab(ui: &mut egui::Ui, d: &mut Document, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        if ui
            .button("Auto-build")
            .on_hover_text("pick charts from the detected column types")
            .clicked()
        {
            actions.push(Action::AutoBuild);
        }
        ui.menu_button("+ add column", |ui| {
            ui.set_min_width(160.0);
            for i in 0..d.column_count() {
                if d.dashboard.panels.iter().any(|p| p.column == i) {
                    continue;
                }
                if ui.button(d.column_name(i)).clicked() {
                    actions.push(Action::AddPanel(i));
                    ui.close();
                }
            }
        });
        ui.separator();
        match (&d.selection, d.filtering()) {
            (Some(s), true) => {
                ui.label(
                    RichText::new(format!(
                        "within selection ({} records)",
                        group_thousands(s.count())
                    ))
                    .color(AMBER),
                );
            }
            _ => {
                ui.label(RichText::new("all records").color(DIM));
            }
        }
        if d.dashboard.running() || d.timeline_job.is_some() {
            ui.spinner();
            ui.label(RichText::new("counting…").color(DIM));
        }
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("charts follow the selection · click a slice or bar to filter by it")
                    .color(DIM)
                    .size(11.5),
            );
        });
    });
    if d.dashboard.panels.is_empty() && d.timestamp_column().is_none() {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "nothing to chart yet — the profile found no categorical, address, domain, port or timestamp columns; add one with “+ add column”",
            )
            .color(DIM),
        );
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("dashboard-scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let avail = ui.available_width();
            if let Some(c) = d.timestamp_column() {
                timeline_card(ui, d, c, avail, actions);
            }
            let cols = (avail / (CARD_MIN_WIDTH + 8.0)).floor().max(1.0) as usize;
            let card_w = (avail - 8.0 * (cols as f32 - 1.0)) / cols as f32 - 1.0;
            let names: Vec<String> = d
                .dashboard
                .panels
                .iter()
                .map(|p| d.column_name(p.column))
                .collect();
            let pivotable: Vec<bool> = d
                .dashboard
                .panels
                .iter()
                .map(|p| p.column < d.header.len())
                .collect();
            // a plain grid of fixed-size cards, each laid out top-down
            for (row, chunk) in d.dashboard.panels.chunks(cols).enumerate() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    for (k, panel) in chunk.iter().enumerate() {
                        let i = row * cols + k;
                        ui.allocate_ui_with_layout(
                            Vec2::new(card_w, CARD_HEIGHT),
                            egui::Layout::top_down(Align::Min),
                            |ui| {
                                ui.set_width(card_w);
                                ui.set_height(CARD_HEIGHT);
                                panel_card(ui, i, panel, &names[i], pivotable[i], actions);
                            },
                        );
                    }
                });
                ui.add_space(8.0);
            }
        });
}

fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(Color32::from_gray(28))
        .stroke(Stroke::new(1.0_f32, Color32::from_gray(52)))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::same(8))
}

/// The timeline as the first, full-width card.
fn timeline_card(
    ui: &mut egui::Ui,
    d: &mut Document,
    column: usize,
    width: f32,
    actions: &mut Vec<Action>,
) {
    let name = d.column_name(column);
    ui.allocate_ui_with_layout(
        Vec2::new(width - 1.0, 140.0),
        egui::Layout::top_down(Align::Min),
        |ui| {
            ui.set_width(width - 1.0);
            card_frame().show(ui, |ui| {
                ui.set_width(width - 18.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&name).monospace().strong());
                    ui.label(RichText::new("timeline").color(DIM).size(11.5));
                    if let Some(v) = &d.timeline {
                        ui.label(
                            RichText::new(format!(
                                "{} events · {}",
                                group_thousands(v.result.parsed),
                                crate::ui::human_width(v.width)
                            ))
                            .color(DIM)
                            .size(11.5),
                        );
                        if let Some((from, to)) = v.snapped() {
                            ui.separator();
                            ui.label(
                                RichText::new(format!(
                                    "{} – {}",
                                    crate::ui::time_label(from as f64, 1),
                                    crate::ui::time_label(to as f64, 1)
                                ))
                                .color(GREEN)
                                .size(11.5),
                            );
                            if ui
                                .small_button(RichText::new("Filter to range").color(AMBER))
                                .clicked()
                            {
                                actions.push(Action::FilterRange(v.column, from, to));
                            }
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("open tab").clicked() {
                            actions.push(Action::Timeline(column));
                        }
                        ui.label(
                            RichText::new("drag to select a range")
                                .color(DIM)
                                .size(11.5),
                        );
                    });
                });
                match &mut d.timeline {
                    Some(v) if d.timeline_job.is_none() => {
                        timeline_plot(ui, v, "dashboard-timeline", 92.0);
                    }
                    _ => {
                        ui.add_space(40.0);
                        ui.horizontal(|ui| {
                            ui.add_space(8.0);
                            ui.spinner();
                            ui.label(RichText::new("bucketing timestamps…").color(DIM));
                        });
                        ui.add_space(40.0);
                    }
                }
            });
        },
    );
    ui.add_space(8.0);
}

fn panel_card(
    ui: &mut egui::Ui,
    index: usize,
    panel: &Panel,
    name: &str,
    pivotable: bool,
    actions: &mut Vec<Action>,
) {
    card_frame().show(ui, |ui| {
        ui.set_min_height(CARD_HEIGHT - 18.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).monospace().strong());
            ui.label(RichText::new(panel.kind.label()).color(DIM).size(11.5));
            if let Some(v) = &panel.view {
                let r = &v.result;
                ui.label(
                    RichText::new(format!(
                        "{} distinct{}",
                        group_thousands(r.distinct),
                        if r.exact { "" } else { " ≈" }
                    ))
                    .color(DIM)
                    .size(11.5),
                );
            }
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button(RichText::new("…").color(DIM), |ui| {
                    ui.set_min_width(140.0);
                    let other = match panel.kind {
                        ChartKind::Pie => ChartKind::Bars,
                        ChartKind::Bars => ChartKind::Pie,
                    };
                    if ui.button(format!("Show as {}", other.label())).clicked() {
                        actions.push(Action::PanelKind(index, other));
                        ui.close();
                    }
                    if ui.button("Open in Values tab").clicked() {
                        actions.push(Action::Count(panel.column));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Remove").clicked() {
                        actions.push(Action::RemovePanel(index));
                        ui.close();
                    }
                });
                if panel.running() {
                    ui.spinner();
                }
            });
        });
        if let Some(e) = &panel.error {
            ui.colored_label(RED, e);
            return;
        }
        let Some(v) = &panel.view else {
            ui.add_space(60.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("counting…").color(DIM));
            });
            return;
        };
        if !v.result.exact {
            ui.label(
                RichText::new(format!(
                    "estimated: counts may be under by up to {}",
                    group_thousands(v.result.error_bound)
                ))
                .size(11.0)
                .color(KHAKI),
            );
        }
        // a click is a search in this column; derived columns cannot be
        // searched, and a chart being recounted must not answer for the
        // old selection
        let clickable = pivotable && !panel.running();
        if !pivotable {
            ui.label(
                RichText::new("derived column: counts only, no click-to-filter")
                    .size(11.0)
                    .color(DIM),
            );
        } else if panel.running() {
            ui.label(
                RichText::new("recounting for the current selection…")
                    .size(11.0)
                    .color(DIM),
            );
        }
        let clicked = match panel.kind {
            ChartKind::Pie => pie_chart(ui, &v.rows, v.result.counted, index, clickable),
            ChartKind::Bars => bar_chart(ui, &v.rows, index, clickable),
        };
        if let (Some(value), true) = (clicked, clickable) {
            actions.push(Action::Pivot(panel.column, value));
        }
    });
}

/// A donut of the top values with a legend; returns the value clicked.
fn pie_chart(
    ui: &mut egui::Ui,
    rows: &[(String, u64, f32)],
    total: u64,
    salt: usize,
    clickable: bool,
) -> Option<String> {
    let total = total.max(1);
    let shown: Vec<(&str, u64)> = rows
        .iter()
        .take(PIE_SLICES)
        .map(|(v, c, _)| (v.as_str(), *c))
        .collect();
    let counted: u64 = shown.iter().map(|(_, c)| c).sum();
    let other = total.saturating_sub(counted);
    // (label, count, colour, is the "everything else" slice)
    let mut slices: Vec<(String, u64, Color32, bool)> = shown
        .iter()
        .enumerate()
        .map(|(i, (v, c))| (v.to_string(), *c, PALETTE[i % PALETTE.len()], false))
        .collect();
    if other > 0 {
        slices.push(("other".into(), other, Color32::from_gray(80), true));
    }

    let mut clicked = None;
    ui.horizontal(|ui| {
        let (rect, resp) = ui.allocate_exact_size(Vec2::splat(PIE_SIZE), Sense::click());
        let centre = rect.center();
        let r_out = PIE_SIZE / 2.0 - 4.0;
        let r_in = r_out * 0.56;
        // which slice is under the pointer: by angle from 12 o'clock
        let hovered = resp.hover_pos().and_then(|p| {
            let v = p - centre;
            let dist = v.length();
            if dist < r_in || dist > r_out {
                return None;
            }
            let mut t = v.y.atan2(v.x) + PI / 2.0;
            if t < 0.0 {
                t += TAU;
            }
            let mut a = 0.0f32;
            slices.iter().position(|(_, c, _, _)| {
                let span = *c as f32 / total as f32 * TAU;
                let hit = t >= a && t < a + span;
                a += span;
                hit
            })
        });
        let painter = ui.painter_at(rect);
        let mut a0 = -PI / 2.0;
        for (i, (_, count, color, _)) in slices.iter().enumerate() {
            let span = *count as f32 / total as f32 * TAU;
            let a1 = a0 + span;
            let (ro, color) = if hovered == Some(i) {
                (r_out + 3.0, color.gamma_multiply(1.25))
            } else {
                (r_out, *color)
            };
            // one convex wedge per slice (two for slices over a half turn)
            // from the centre; the hole is painted over afterwards, so there
            // are no seams inside a slice
            let parts = if span > PI { 2 } else { 1 };
            let pt = |r: f32, a: f32| Pos2::new(centre.x + r * a.cos(), centre.y + r * a.sin());
            for part in 0..parts {
                let s0 = a0 + span * part as f32 / parts as f32;
                let s1 = a0 + span * (part + 1) as f32 / parts as f32;
                let n = (((s1 - s0) / TAU) * 96.0).ceil().max(2.0) as usize;
                let mut pts = Vec::with_capacity(n + 2);
                pts.push(centre);
                for k in 0..=n {
                    pts.push(pt(ro, s0 + (s1 - s0) * k as f32 / n as f32));
                }
                painter.add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
            }
            a0 = a1;
        }
        painter.circle_filled(centre, r_in, Color32::from_gray(28));
        // separators between slices
        let mut a = -PI / 2.0;
        for (_, count, _, _) in &slices {
            let span = *count as f32 / total as f32 * TAU;
            painter.line_segment(
                [
                    Pos2::new(centre.x + r_in * a.cos(), centre.y + r_in * a.sin()),
                    Pos2::new(
                        centre.x + (r_out + 3.0) * a.cos(),
                        centre.y + (r_out + 3.0) * a.sin(),
                    ),
                ],
                Stroke::new(1.5_f32, Color32::from_gray(28)),
            );
            a += span;
        }
        painter.text(
            centre,
            egui::Align2::CENTER_CENTER,
            group_thousands(total),
            egui::FontId::monospace(12.0),
            CELL_TEXT,
        );
        if let Some(h) = hovered {
            let (label, count, _, is_other) = &slices[h];
            resp.clone().on_hover_text(format!(
                "{label}\n{} · {:.1}%",
                group_thousands(*count),
                *count as f64 / total as f64 * 100.0
            ));
            if resp.clicked() && clickable && !is_other {
                clicked = Some(label.clone());
            }
        }

        // legend
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            for (i, (label, count, color, is_other)) in slices.iter().enumerate() {
                let is_hot = hovered == Some(i);
                ui.horizontal(|ui| {
                    let (sw, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().rect_filled(sw, 2.0, *color);
                    let text = RichText::new(shorten(label, 22))
                        .monospace()
                        .size(11.5)
                        .color(if is_hot { AMBER } else { CELL_TEXT });
                    let r = ui.add(egui::Label::new(text).sense(Sense::click()));
                    if r.clicked() && clickable && !is_other {
                        clicked = Some(label.clone());
                    }
                    ui.label(
                        RichText::new(format!("{:.1}%", *count as f64 / total as f64 * 100.0))
                            .size(11.0)
                            .color(DIM),
                    );
                });
            }
        });
        let _ = salt;
    });
    clicked
}

/// Horizontal bars of the top values; returns the value clicked.
fn bar_chart(
    ui: &mut egui::Ui,
    rows: &[(String, u64, f32)],
    salt: usize,
    clickable: bool,
) -> Option<String> {
    let rows: Vec<&(String, u64, f32)> = rows.iter().take(BAR_ROWS).collect();
    if rows.is_empty() {
        ui.label(RichText::new("no values").color(DIM));
        return None;
    }
    let max = rows.iter().map(|r| r.1).max().unwrap_or(1).max(1) as f32;
    let row_h = ((CARD_HEIGHT - 50.0) / rows.len() as f32).clamp(14.0, 20.0);
    let width = ui.available_width();
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(width, row_h * rows.len() as f32), Sense::hover());
    let painter = ui.painter_at(rect);
    let label_w = (width * 0.42).min(150.0);
    let count_w = 62.0;
    let bar_w = (width - label_w - count_w - 12.0).max(20.0);
    let font = egui::FontId::monospace(11.5);
    let mut clicked = None;
    for (i, (value, count, share)) in rows.iter().enumerate() {
        let y0 = rect.top() + i as f32 * row_h;
        let row = Rect::from_min_size(Pos2::new(rect.left(), y0), Vec2::new(width, row_h));
        let id = ui.id().with(("bar", salt, i));
        let resp = ui.interact(row, id, Sense::click());
        let hot = resp.hovered();
        if hot {
            painter.rect_filled(row, 2.0, Color32::from_gray(40));
        }
        painter.text(
            Pos2::new(row.left() + 2.0, row.center().y),
            egui::Align2::LEFT_CENTER,
            shorten(value, (label_w / 7.0) as usize),
            font.clone(),
            if hot { AMBER } else { CELL_TEXT },
        );
        let bar = Rect::from_min_size(
            Pos2::new(row.left() + label_w + 6.0, y0 + 3.0),
            Vec2::new(bar_w * (*count as f32 / max), row_h - 6.0),
        );
        painter.rect_filled(
            bar,
            2.0,
            if hot {
                AMBER.gamma_multiply(1.2)
            } else {
                AMBER
            },
        );
        painter.text(
            Pos2::new(row.right() - 2.0, row.center().y),
            egui::Align2::RIGHT_CENTER,
            group_thousands(*count),
            font.clone(),
            DIM,
        );
        let resp = resp.on_hover_text(format!(
            "{value}\n{} · {:.2}%",
            group_thousands(*count),
            share * 100.0
        ));
        if resp.clicked() && clickable {
            clicked = Some(value.clone());
        }
    }
    clicked
}

fn shorten(s: &str, max: usize) -> String {
    let max = max.max(4);
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max - 1).collect();
        format!("{head}…")
    }
}
