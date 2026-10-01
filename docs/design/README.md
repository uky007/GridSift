# Desktop UI design — v1

Status: implemented in `crates/gridsift/src/bin/gridsift-desktop` (2026-09-28); `mock-v1.html`
next to this file is the static mock the implementation was checked against.
Deviations from the proposal are listed at the end.

## What the v0 shell got wrong (historical)

This section is the proposal's starting point, kept for the record: it
describes the v0 shell that preceded this design, not the current
application. The v0 shell grew feature by feature. It worked, but:

1. **The top panel is a pile.** Four rows of controls (file bar, evidence
   facts, search, count/timeline) plus badges take a third of the window
   before the first row of data, and nothing distinguishes *facts about the
   evidence* from *things you can do to it*.
2. **The investigation is invisible.** The current selection ("beacon" →
   time range → …) exists as a lineage in memory and in the manifest, but on
   screen it is one status line. An analyst cannot see, remove or revisit a
   step.
3. **Analysis surfaces are ad hoc.** Timeline and value counts are two
   independent bottom panels with their own headers and close buttons; the
   profile lives in the column headers only.
4. **Per-column actions are scattered.** Counting, timeline, enrichment and
   redaction all start from separate widgets, though every one of them is
   "do X with column Y".
5. **The empty state says nothing.** A drop hint, no statement of what the
   tool promises.

## Principles

- **Evidence first, actions second.** Facts about the file are always
  visible and visually distinct from controls.
- **The selection lineage is the UI.** Every filtering step is a chip in a
  breadcrumb; the manifest is literally what is on screen.
- **Columns are the handles.** A column is the unit of investigation:
  count it, chart it, enrich it, redact it — from one place.
- **Bounded, honest numbers.** Timing and memory stay in the status bar;
  approximate results say so.
- **Dark, monospace data, few colours with fixed meanings** (see below).

## Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ gridsift  proxy_2026.csv  108.4 GB   [EVIDENCE · READ ONLY] [STRICT OFFLINE] ⋯ │  title bar
├───────────────┬──────────────────────────────────────────────────────────────┤
│ EVIDENCE      │ ⌕ search…                   [Regex] [Aa] [Invert] [column ▾] │  command bar
│ Records 812M  │ ▸ "/c2/beacon" 483,485 ▸ timestamp 09-22 14:00–16:00 12,331  │  lineage chips
│ SHA-256 b7f…✓ │   [show only matches ✓]                    [× clear]          │
│ Index ✓ 1.05s ├──────────────────────────────────────────────────────────────┤
│ Dialect , "   │ #   timestamp           src_ip        dst_ip      host   …   │  grid
│ Malformed 0   │ 5   2026-09-21T14:13:26Z 10.5.65.5    192.0.2.158 cdn.exam… │
│               │ …                                                            │
│ COLUMNS       │                                                              │
│ timestamp  ts │                                                              │
│ src_ip   ipv4 │                                                              │
│ dst_ip   ipv4 │                                                              │
│ host   domain │                                                              │
│ …             ├──────────────────────────────────────────────────────────────┤
│ ENRICHMENT    │ [Timeline] [Values] [Profile]                                │  analysis dock
│ src_ip → geo  │  ▂▃▅▇▇▆▃▂▁  (chart / table for the current selection)         │  (tabs)
│ host → PSL    │                                                              │
│ [+ add]       │                                                              │
│ [Export…]     │                                                              │
├───────────────┴──────────────────────────────────────────────────────────────┤
│ first rows 3.6 ms · index 1.05 s · 1,000 rows cached · peak RSS 149 MiB      │  status bar
└──────────────────────────────────────────────────────────────────────────────┘
```

### Title bar
File name, size, the two badges. Open / Close / About move into an overflow
menu (⋯); they are rare actions.

### Evidence sidebar (left, always visible, resizable)
Three sections, facts only:

- **Evidence**: records (live while indexing, with the progress bar in
  place), SHA-256 (✓ once computed, "computing 37 %" before), index state
  and time, dialect, malformed counts. Nothing here is a control.
- **Columns**: one row per column — name, detected type, confidence —
  derived columns in green below the source ones. A click opens the column
  menu: *Count values · Timeline · Search in this column · Enrich… · Redact
  on export…*. This replaces the "Count values of / Timeline of" combos.
- **Enrichment**: the active rules (column → provider → dataset), each
  removable, plus *add*. Below it the **Export…** button: the only
  "produce an artefact" action, so it sits with the other file-level facts.

### Command bar (top of the main area)
One search field with its chips (Regex, Aa, Invert, column). Below it the
**selection lineage** as breadcrumb chips: every step with its match count
(`"/c2/beacon" 483,485 ▸ timestamp 09-22 14:00–16:00 12,331`). Clicking a
chip reverts to that step; × on the last chip removes it; *clear* drops the
selection. "Show only matches" and Prev/Next live here too. The lineage is
exactly what the export manifest will record.

### Grid
Unchanged in function: virtual rows, typed headers (type + confidence on a
second line), derived columns in green, matches in amber.

### Analysis dock (bottom, resizable, tabbed)
Tabs in order: Values, Dashboard, Timeline, Profile. The dock opens on
Values — not everyone wants charts, and charts cost scans — while the
dashboard is built from the file-wide profile and counted in the
background, on screen or not, so opening it shows current charts at once.

- **Dashboard** (added after v1): cards picked from the profile — the
  timeline, pies for columns with a handful of values, top-value bars for
  hosts / addresses / ports — counted over the current selection and
  refreshed when it changes; a click on a slice or bar is a new step.
  Charts are painted directly (`dashboard.rs`) so slices and bars are
  hoverable and clickable; the timeline card reuses the Timeline tab's
  plot.
- **Timeline**: chart of the current selection; drag → range chip
  ("Filter to range" becomes implicit: releasing the drag shows a floating
  *Filter* button on the selection).
- **Values**: top-N of a column with count / share / bar; click → filter
  chip. Header shows exact vs estimated and the error bound.
- **Profile**: the full column profile table (type, confidence, distinct,
  max length, examples) — currently only reachable through the CLI.

The dock remembers which tab was last used; an analysis started from a
column menu opens the right tab.

### Status bar
Performance and integrity facts only: first rows, index time, rows cached,
peak RSS, and a pending-work spinner (indexing / searching / counting).

### Empty state
A large drop target and three lines: *never modified · never uploaded ·
never resolved*. Later: recent files.

### Dialogs
- **Export…** becomes a summary: the lineage (from the chips), record
  count, redaction table (per column, defaults from the column menu's
  "Redact on export" choices), enrichment columns to include, output path,
  and what the manifest will contain. One page, then the file picker.
- **Enrich…** stays a dialog (rare, needs file pickers).

## Colour and type

| meaning | colour |
|---|---|
| source data | light grey monospace |
| selection / matches / analysis marks | amber `#f5c850` |
| derived (enrichment) columns | green `#78c88c` |
| evidence / integrity badges | teal `#2e8b57`, blue `#4682b4` |
| warnings (malformed, estimated) | khaki |
| errors | light red |

Dark theme only until there is a light palette designed for the data grid.

## How it is built

The crate is split by responsibility; panels only draw and return
`ui::Action`s, which the app applies after the frame:

| file | holds |
|---|---|
| `theme.rs` | the colour table above, badge / chip / section / bar widgets, `CMD` (⌘ or Ctrl+) |
| `cache.rs` | `RowCache`: decoded rows by ordinal, window and scattered fills |
| `jobs.rs` | background jobs: `BuildJob`, `SelectionNode` (the chain), freq / timeline / export jobs and views |
| `document.rs` | `Document`: the open file, its index, selection, dialog state; start/poll for every job |
| `ui.rs` | title bar, evidence sidebar, command bar + lineage chips, grid, analysis dock, status bar, empty state |
| `dialogs.rs` | Export (lineage summary + redaction) and Enrich dialogs |
| `main.rs` | launch args, `App`, action dispatch |

- The selection is a chain of `Arc<SelectionNode>` (`parent`, `op`, match
  set, join handle). A chip reverts to an ancestor by pointing at its node
  — no rescans. A new step started while the current one is still
  scanning cancels it and nests in its (finished) parent.
- Counts and timelines started while a scan runs nest in it correctly: the
  worker thread waits for the selection to finish before reading its match
  set. Export is disabled while a scan runs, so what the dialog shows is
  what gets written.
- "Show only matches" is switched on whenever a step is created; highlight
  mode (prev / next) is a toggle away.
- A step's state (running / complete / cancelled / failed) is explicit
  (`SelectionState`). Cancelled and failed steps are drawn in khaki with a
  label, and nothing downstream — export, counts, timelines, nested
  searches — accepts a lineage that contains one.
- The search field has an *Exact* chip (whole-field equality); a click in
  the Values tab uses it, so the pivot selects exactly the count shown.
- The sidebar checks the source's size and modification time every two
  seconds (and every scan checks before starting); a change shows a red
  banner, cancels running work and disables export until the file is
  reopened.
- Opening a dataset for enrichment runs on a worker thread; the dialog
  shows a spinner and keeps the UI responsive for large MMDB / CSV files.

## Deviations from the proposal, and open points

1. **Filter to range** stays an explicit button in the timeline header
   (the floating button on the drag selection was not worth the extra
   plot-overlay code).
2. The Columns section scrolls together with the rest of the sidebar; a
   separate scroll region is still open for files with 150+ columns.
3. egui's bundled fonts lack several symbols in the proportional family
   (`✓ ⋯ ✕ ⌕ ▸`); the UI uses `✔ ☰ ✖ 🔍 ▶` instead. Check
   `epaint_default_fonts` coverage before adding a glyph.
4. Japanese UI strings: English only for now.
5. The dock does not yet remember its height between files.
