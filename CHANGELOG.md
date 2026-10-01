# Changelog

All notable changes to gridsift are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) once 1.0 is reached — before
that, minor versions may change interfaces and the manifest format.

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

[0.1.0]: https://github.com/uky007/GridSift/releases/tag/v0.1.0
