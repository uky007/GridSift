# Changelog

All notable changes to gridsift are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) once 1.0 is reached — before
that, minor versions may change interfaces and the manifest format.

## [Unreleased]

### Packaging
- One package, `gridsift`, now carries both binaries: `cargo install
  gridsift` installs the desktop application and the command-line tool,
  and `cargo run` starts the application (`default-run`). The
  `gridsift-desktop` package is gone; the binary names are unchanged.

### Analysis cache
- Whole-file results are kept in the user cache directory beside the index
  sidecar: the file-wide column profile and value counts (`*.gsan`) and
  the timelines over all records (`*.gstl`, read only when a timeline is
  asked for). The next open of the same bytes — same
  size, modification time and SHA-256 — shows the dashboard and timeline
  at once and starts no profile pass; `freq`, `timeline` and `profile`
  report `cached`. Counts over a selection or of derived columns are
  always recomputed, and a changed file never uses the cache.

### Files without a header
- The sniffer's reading of the first record can be overridden everywhere:
  `--header` / `--no-header` on the desktop launch line as on the command
  line, and a click on *header* / *no header* in the sidebar reopens the
  file the other way. `--names a,b,c` (command line and desktop launch
  line) and the sidebar's *name columns…* dialog name the columns of a
  file without a header; the names resolve `-c` and are recorded in the
  manifest of every export (`source.dialect.names`), never in the file.

### Desktop (`gridsift-desktop`)
- The analysis dock is open from the start, on *Values*, now the first tab
  and with its own column picker; *Analysis* in the command bar hides and
  shows it. The dashboard is built from the file-wide profile and
  counted in the background, on screen or not, so opening it shows current
  charts at once; the panels are counted one after another (one count's
  memory instead of six), and a timeline the analyst moved to another
  column is left alone by the background recount while the dashboard is
  off screen.

## [0.1.0] — 2026-10-01

First public release.

### Engine (`gridsift-core`)
- Dialect sniffing (delimiter, quoting, header) with explicit overrides.
- Quote-aware sparse index (checkpoints every 4,096 records / 4 MiB with
  parser state) and a bootstrap index for instant first rows; SHA-256 /
  BLAKE3 computed in the same pass on a separate thread.
- Parallel literal, regex and exact-field search into a roaring bitmap of
  record ordinals; nested selections.
- Value counts (exact, then lossy counting with a stated error bound;
  HyperLogLog distinct estimate), timelines with automatic bucket
  coarsening, semantic column typing from a file-wide sample.
- Offline enrichment: GeoIP / ASN from an imported MMDB, Public Suffix
  List domains, local CSV lookups — every dataset recorded by hash.
- Export of exact source bytes (or redacted / enriched records) with a
  provenance manifest published before the output; `verify` recomputes
  digests and states its scope.
- Redaction: drop, mask, partial, IP prefix, HMAC pseudonyms (key
  fingerprint only in the manifest).
- Evidence protection: every write target — output, manifest, index
  sidecar, temporaries — is checked against the source by path and file
  identity; a source changed on disk is detected before scans and
  exports.
- Deterministic synthetic datasets (`narrow`, `wide`, `quotes`, `ragged`,
  and `demo` with reserved example hosts and TEST-NET addresses).

### Command line (`gridsift`)
- `info`, `index`, `rows`, `search`, `freq`, `timeline`, `profile`,
  `export`, `verify`, `count`, `hash`, `gen`; `--json` everywhere; index
  sidecars keyed by file and parser settings.

### Desktop (`gridsift-desktop`)
- Evidence sidebar, command bar with the selection lineage as chips,
  virtual grid, analysis dock with Dashboard (charts picked from the
  column types, following the selection, click-to-filter), Timeline,
  Values and Profile tabs; export and enrichment dialogs.

### Known limitations
- Input is treated as bytes (UTF-8 assumed for display); no UTF-16, no
  compressed input; no whole-file sort or join; manifests are unsigned.
- Measured to 10 GiB on a warm cache; the 100 GB cold-cache run is
  pending (see `docs/roadmap.md`).

[Unreleased]: https://github.com/uky007/GridSift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/uky007/GridSift/releases/tag/v0.1.0
