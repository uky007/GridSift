# Roadmap

The project is being built towards a conference-demo-ready 1.0 in the
first half of 2027. "Implemented" means merged on `main` with tests and a
number in [../bench/README.md](../bench/README.md) where one applies.

## Phase 0 — engine gate (implemented)

The go / no-go criteria for the whole project:

1. Open a 100 GB-class CSV with bounded memory — **engine implemented,
   100 GB not yet measured**: measured to 10 GiB (index pass ~35 MiB with
   the digest, ~10 MiB without, the same at 1 and 10 GiB); the 100 GB
   cold-cache run is pending external storage.
2. First rows in under 2 s — **implemented** (milliseconds, via the
   bootstrap index).
3. Quote-aware sparse index with random access — **implemented**;
   checkpoints carry parser state, verified against the `csv` crate on
   torture and random input.
4. Source digest in the same pass — **implemented**; SHA-256 on its own
   thread, BLAKE3 optional.

## Phase 1 — investigation (implemented)

- Parallel literal / regex search with column restriction, case folding
  and inversion; roaring bitmap match sets — **implemented**
- Export of exact source bytes with a provenance manifest; `verify` —
  **implemented**
- Semantic column typing from a file-wide sample — **implemented**
- Value counts (exact → lossy, HyperLogLog distinct) — **implemented**
- Export-time redaction: drop / mask / partial / ip-prefix / hmac —
  **implemented**
- Offline enrichment: GeoIP / ASN (MMDB), Public Suffix List, CSV lookups —
  **implemented**
- Timeline: timestamp parsing, bucketed counts, time-range selection —
  **implemented**
- Desktop application with the evidence sidebar, selection lineage, grid
  and analysis dock — **implemented** ([design/README.md](design/README.md))
- Dashboard: charts picked from the column types, following the
  selection, click-to-filter — **implemented**

## Phase 2 — before the demo

- **100 GB validation** on external storage with a cold page cache; publish
  the numbers (open, index, search, export) and the RSS ceiling.
- **Real GeoIP databases** (GeoLite2 City / ASN) exercised end to end and
  benchmarked.
- **Windows and Linux numbers** in the benchmark table (CI already builds
  and tests on all three).
- **Analyst annotations** as a sidecar overlay: tags and notes on records
  that travel with the case and appear in the export manifest, without
  touching the source.
- **Signed manifests** (optional key) so an exported finding can be
  attributed as well as verified.
- **Share-safe manifest variant**: relative paths and hashed query terms
  for a manifest that leaves the case boundary, next to the complete one
  that stays with the case.
- **Project hygiene**: CONTRIBUTING, SECURITY, CHANGELOG, the MSRV CI job
  and crates.io packaging exist; still to do — locked dependencies for
  release builds and a dependency audit (`cargo audit` / `cargo deny`) in
  CI.
- **UTF-16 / encoding handling** and compressed input (`.gz`).
- **Packaging**: signed macOS / Windows builds, a Linux AppImage or static
  binary; a release workflow that attaches them to GitHub releases.
- Desktop polish from the v1 design's open points: dock height memory,
  separate scrolling for very wide files, recent files.

## Later

- **SQL over a selection** through an embedded out-of-core engine (DuckDB),
  keeping the source CSV authoritative and recording the query in the
  manifest.
- **Whole-file sort and join** (external, bounded memory).
- **Multi-file cases**: several evidence files in one window, cross-file
  lookups, one manifest tree.
- **Sandboxed extensions** (WebAssembly) for custom enrichers and
  detectors, with capability limits so an extension cannot reach the
  network or the source file.
- **Offline PTR / hostname packs**: reverse-DNS snapshots imported as data
  packs, never resolved live.
- **Air-gap update packs**: signed bundles of enrichment datasets with
  their hashes recorded in the manifest.
