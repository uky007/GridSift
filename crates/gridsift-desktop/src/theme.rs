//! Colours with fixed meanings, and the few shared widgets that use them.
//!
//! | meaning | colour |
//! |---|---|
//! | source data | light grey monospace |
//! | selection / matches / analysis marks | amber |
//! | derived (enrichment) columns | green |
//! | evidence / integrity badges | teal, blue |
//! | warnings (malformed, estimated) | khaki |
//! | errors | light red |

use eframe::egui::{self, Color32, RichText, Sense, Stroke};

pub const AMBER: Color32 = Color32::from_rgb(0xf5, 0xc8, 0x50);
pub const GREEN: Color32 = Color32::from_rgb(0x78, 0xc8, 0x8c);
pub const TEAL: Color32 = Color32::from_rgb(0x2e, 0x8b, 0x57);
pub const BLUE: Color32 = Color32::from_rgb(0x46, 0x82, 0xb4);
pub const KHAKI: Color32 = Color32::from_rgb(0xc9, 0xb4, 0x58);
pub const RED: Color32 = Color32::from_rgb(0xff, 0x80, 0x80);
pub const HEADER_TEXT: Color32 = Color32::from_gray(235);
pub const ROW_NUMBER_TEXT: Color32 = Color32::from_gray(120);
pub const CELL_TEXT: Color32 = Color32::from_gray(210);
pub const DIM: Color32 = Color32::from_gray(140);
pub const PANEL: Color32 = Color32::from_rgb(0x16, 0x19, 0x1c);

pub const ROW_HEIGHT: f32 = 18.0;
pub const HEADER_HEIGHT: f32 = 34.0;

/// Small filled label used for the evidence / offline badges.
pub fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
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

/// Sidebar section heading.
pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).size(10.5).strong().color(DIM));
    ui.add_space(2.0);
}

/// Key/value fact line in the sidebar.
pub fn fact(ui: &mut egui::Ui, key: &str, value: impl Into<RichText>) {
    ui.label(RichText::new(key).color(DIM));
    ui.label(value.into().monospace());
    ui.end_row();
}

/// A bordered chip. Returns `(body clicked, close clicked)`.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32, closable: bool) -> (bool, bool) {
    let mut clicked = false;
    let mut closed = false;
    egui::Frame::NONE
        .stroke(Stroke::new(1.0_f32, color))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let r = ui.add(
                    egui::Label::new(RichText::new(text).monospace().size(12.0).color(color))
                        .sense(Sense::click()),
                );
                if r.clicked() {
                    clicked = true;
                }
                if closable {
                    let x = ui
                        .add(egui::Label::new(RichText::new("×").color(DIM)).sense(Sense::click()));
                    if x.on_hover_text("remove this step").clicked() {
                        closed = true;
                    }
                }
            });
        });
    (clicked, closed)
}

/// A toggle rendered as a chip.
pub fn toggle_chip(ui: &mut egui::Ui, on: &mut bool, text: &str) -> bool {
    let color = if *on { AMBER } else { DIM };
    let (clicked, _) = chip(ui, text, color, false);
    if clicked {
        *on = !*on;
    }
    clicked
}

/// The primary shortcut modifier, as shown in labels (`Modifiers::COMMAND`).
pub const CMD: &str = if cfg!(target_os = "macos") {
    "⌘"
} else {
    "Ctrl+"
};

/// A plain horizontal bar (no animation, no rounding artefacts for tiny
/// values), used for value-count shares.
pub struct Bar {
    fraction: f32,
    width: Option<f32>,
}

impl Bar {
    pub fn new(fraction: f32) -> Bar {
        Bar {
            fraction: fraction.clamp(0.0, 1.0),
            width: None,
        }
    }

    pub fn desired_width(mut self, width: f32) -> Bar {
        self.width = Some(width);
        self
    }
}

impl egui::Widget for Bar {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let width = self.width.unwrap_or_else(|| ui.available_width());
        let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 10.0), Sense::hover());
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            painter.rect_filled(rect, 2.0, Color32::from_gray(40));
            let mut filled = rect;
            filled.set_width((rect.width() * self.fraction).max(1.0));
            painter.rect_filled(filled, 2.0, AMBER);
        }
        response
    }
}
