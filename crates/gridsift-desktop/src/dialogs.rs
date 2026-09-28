//! The two dialogs: export (with lineage summary and redaction) and enrich.

use eframe::egui::{self, RichText};
use gridsift_core::enrich::Provider;
use gridsift_core::redact::{RedactMethod, Redactor};
use gridsift_core::sys::group_thousands;

use crate::document::{Document, ProviderChoice, RuleChoice};
use crate::theme::{AMBER, DIM, GREEN, RED};

/// The export dialog: what will be written, how it is redacted, then the
/// file picker.
pub fn export_window(ctx: &egui::Context, d: &mut Document) {
    if !d.export_ui.open {
        return;
    }
    let mut open = true;
    let mut go = false;
    let mut cancel = false;
    let filtering = d.filtering();
    egui::Window::new("Export finding")
        .collapsible(false)
        .resizable(true)
        .default_width(660.0)
        .open(&mut open)
        .show(ctx, |ui| {
            // -- what
            ui.label(RichText::new("Records").strong());
            match (&d.selection, filtering) {
                (Some(sel), true) => {
                    ui.label(format!(
                        "{} records selected by:",
                        group_thousands(sel.count())
                    ));
                    for (k, node) in sel.lineage().iter().enumerate() {
                        ui.label(
                            RichText::new(format!(
                                "  {} {}   {}",
                                if k == 0 { "•" } else { "▸" },
                                node.op.describe(&d.header),
                                group_thousands(node.count())
                            ))
                            .monospace()
                            .color(AMBER),
                        );
                    }
                }
                _ => {
                    ui.label("all records (no selection is being applied)");
                }
            }
            if !d.derived_names.is_empty() {
                ui.checkbox(
                    &mut d.export_ui.include_derived,
                    format!("append the {} derived columns", d.derived_names.len()),
                );
            }
            ui.separator();

            // -- redaction
            ui.label(RichText::new("Redaction").strong());
            ui.label(
                RichText::new(
                    "Untouched columns keep their exact bytes. Redacted columns are rewritten; \
                     the manifest records the policy (never the key).",
                )
                .color(DIM),
            );
            egui::ScrollArea::vertical()
                .id_salt("redact-scroll")
                .max_height(220.0)
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
                                ui.label(RichText::new(typed).color(DIM));
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
            egui::Grid::new("redact-params")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("mask text").color(DIM));
                    ui.text_edit_singleline(&mut d.export_ui.mask_text);
                    ui.end_row();
                    ui.label(RichText::new("partial: characters kept").color(DIM));
                    ui.add(egui::DragValue::new(&mut d.export_ui.keep).range(0..=64));
                    ui.end_row();
                    ui.label(RichText::new("ip prefix bits").color(DIM));
                    ui.add(egui::DragValue::new(&mut d.export_ui.bits).range(0..=128));
                    ui.end_row();
                    ui.label(RichText::new("hmac length (hex chars)").color(DIM));
                    ui.add(egui::DragValue::new(&mut d.export_ui.hmac_len).range(1..=64));
                    ui.end_row();
                    ui.label(RichText::new("hmac key").color(DIM));
                    ui.add(
                        egui::TextEdit::singleline(&mut d.export_ui.hmac_key)
                            .password(true)
                            .desired_width(300.0)
                            .hint_text("kept in memory only"),
                    );
                    ui.end_row();
                });
            ui.separator();

            // -- what the manifest will say
            ui.label(RichText::new("Manifest").strong());
            let n_rules = d.export_ui.choices.iter().filter(|c| **c != RuleChoice::Keep).count();
            ui.label(
                RichText::new(format!(
                    "source identity (size, mtime, SHA-256) · parser settings · {} selection step(s) · {} enrichment rule(s) · {} redaction rule(s) · output SHA-256",
                    d.selection.as_ref().filter(|_| filtering).map_or(0, |s| s.lineage().len()),
                    if d.export_ui.include_derived { d.enrichment.as_ref().map_or(0, |e| e.rules().len()) } else { 0 },
                    n_rules
                ))
                .color(DIM),
            );
            if let Some(e) = &d.export_ui.error {
                ui.colored_label(RED, e);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Choose file & export…").color(AMBER)).clicked() {
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
    let stem = d
        .path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".into());
    let name = format!(
        "{stem}-{}{}.csv",
        if filtering { "finding" } else { "all" },
        if rules.is_empty() { "" } else { "-redacted" }
    );
    if let Some(p) = rfd::FileDialog::new()
        .set_file_name(name)
        .add_filter("CSV", &["csv"])
        .save_file()
    {
        d.export_ui.open = false;
        d.export_ui.error = None;
        let include_derived = d.export_ui.include_derived;
        d.start_export(p, rules, key, include_derived);
    }
}

/// The enrichment dialog: assemble rules, apply them to the document.
pub fn enrich_window(ctx: &egui::Context, d: &mut Document) {
    if !d.enrich_ui.open {
        return;
    }
    let mut open = true;
    let (mut apply, mut add, mut close) = (false, false, false);
    let mut remove: Option<usize> = None;
    egui::Window::new("Enrich")
        .collapsible(false)
        .resizable(true)
        .default_width(680.0)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(
                RichText::new(
                    "Derived columns are computed from local data only and appended after the \
                     source columns. The manifest records which dataset (by hash) produced them.",
                )
                .color(DIM),
            );
            ui.separator();
            if d.enrich_ui.rules.is_empty() {
                ui.label(RichText::new("no rules yet").color(DIM));
            }
            for (i, r) in d.enrich_ui.rules.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.monospace(&r.name);
                    ui.label(RichText::new(format!("→ {}", r.provider.label())).monospace());
                    let dataset = match &r.provider {
                        Provider::GeoIp(p) => {
                            let info = p.info();
                            format!("{} ({})", info.name, info.database_type.as_deref().unwrap_or("mmdb"))
                        }
                        Provider::Lookup(t) => format!("{} ({} keys)", t.info().name, t.len()),
                        Provider::Domain => format!("public suffix list {}", gridsift_core::enrich::PSL_VERSION),
                    };
                    ui.label(RichText::new(dataset).color(GREEN));
                    if ui.small_button("remove").clicked() {
                        remove = Some(i);
                    }
                });
            }
            ui.separator();
            ui.label(RichText::new("Add a rule").strong());
            ui.horizontal(|ui| {
                ui.label(RichText::new("column").color(DIM));
                let name = d
                    .header
                    .get(d.enrich_ui.column)
                    .cloned()
                    .unwrap_or_default();
                egui::ComboBox::from_id_salt("enrich-column")
                    .selected_text(name)
                    .width(170.0)
                    .show_ui(ui, |ui| {
                        for (i, n) in d.header.iter().enumerate() {
                            ui.selectable_value(&mut d.enrich_ui.column, i, n);
                        }
                    });
                ui.label(RichText::new("provider").color(DIM));
                egui::ComboBox::from_id_salt("enrich-provider")
                    .selected_text(d.enrich_ui.choice.label())
                    .width(230.0)
                    .show_ui(ui, |ui| {
                        for c in ProviderChoice::ALL {
                            ui.selectable_value(&mut d.enrich_ui.choice, c, c.label());
                        }
                    });
            });
            let chosen = d
                .enrich_ui
                .path
                .as_ref()
                .map_or("no file chosen".to_string(), |p| p.display().to_string());
            match d.enrich_ui.choice {
                ProviderChoice::GeoIp => {
                    ui.horizontal(|ui| {
                        if ui.button("Choose .mmdb…").clicked() {
                            if let Some(p) = rfd::FileDialog::new().add_filter("MaxMind DB", &["mmdb"]).pick_file() {
                                d.enrich_ui.path = Some(p);
                            }
                        }
                        ui.label(RichText::new(chosen).color(DIM));
                    });
                    ui.label(
                        RichText::new("GeoLite2 / DB-IP Lite in MMDB format. Import your own copy — nothing is bundled.")
                            .color(DIM),
                    );
                }
                ProviderChoice::Domain => {
                    ui.label(
                        RichText::new("registrable domain, public suffix and subdomain from the bundled Public Suffix List snapshot")
                            .color(DIM),
                    );
                }
                ProviderChoice::Lookup => {
                    ui.horizontal(|ui| {
                        if ui.button("Choose CSV…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("Delimited text", &["csv", "tsv", "txt"])
                                .pick_file()
                            {
                                d.enrich_ui.path = Some(p);
                            }
                        }
                        ui.label(RichText::new(chosen).color(DIM));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("key column").color(DIM));
                        ui.add(
                            egui::TextEdit::singleline(&mut d.enrich_ui.key)
                                .desired_width(120.0)
                                .hint_text("name or index"),
                        );
                        ui.label(RichText::new("value columns").color(DIM));
                        ui.add(
                            egui::TextEdit::singleline(&mut d.enrich_ui.values)
                                .desired_width(240.0)
                                .hint_text("comma-separated; empty = all"),
                        );
                    });
                }
            }
            let loading = d.enrich_ui.loading.is_some();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new("Add rule"))
                    .clicked()
                {
                    add = true;
                }
                if loading {
                    ui.spinner();
                    ui.label(RichText::new("opening the dataset…").color(DIM));
                }
            });
            if let Some(e) = &d.enrich_ui.error {
                ui.colored_label(RED, e);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !loading,
                        egui::Button::new(RichText::new("Apply").color(AMBER)),
                    )
                    .clicked()
                {
                    apply = true;
                }
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        });
    if let Some(i) = remove {
        d.enrich_ui.rules.remove(i);
    }
    if add {
        let header = d.header.clone();
        d.enrich_ui.start_loading(&header);
    }
    d.enrich_ui.poll_loading();
    if d.enrich_ui.loading.is_some() {
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
    if apply {
        d.apply_enrichment();
        d.enrich_ui.open = false;
    }
    if !open || close {
        d.enrich_ui.open = false;
    }
}
