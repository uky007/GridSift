# Survey of existing tools

> Status note (September 2026): the entries below are based on project
> READMEs, release notes and official product pages as of late September
> 2026. Size and speed figures are the projects' own claims, measured on
> different hardware and data; they are not comparable with each other or
> with gridsift's numbers, and "active" is an approximate maintenance
> signal, not a quality judgement.

## Why gridsift?

Opening a multi-gigabyte CSV is no longer novel: several viewers and editors
do it, some far beyond 100 GB. What the survey did not find is a tool that
combines, in one open-source cross-platform application, the four things a
forensic investigation of a large delimited export needs:

1. **bounded-memory, quote-aware navigation** of files larger than RAM;
2. **an interactive investigation flow** — search, pivot, time window,
   value counts — rather than a viewer or a batch CLI;
3. **strict offline operation with local enrichment** (GeoIP / ASN, domain
   classification, local lookups) identified by dataset hash;
4. **evidence handling by construction** — read-only source, digest on open,
   a provenance manifest for every export.

Each existing tool covers one or two of these. gridsift's position is the
intersection.

## Desktop viewers and editors

| Tool | License | Platforms | Large-file approach (project claims) | Positioning |
|---|---|---|---|---|
| **EmEditor** | proprietary (Free / Professional) | Windows | up to 16 TB / ~1.1 trillion lines; partial loading, multithreading, SIMD; vendor benchmarks open 10–50 GB files in seconds | the performance reference for huge text and CSV editing; Windows-only, not OSS |
| **Modern CSV v3** | proprietary (Free / Premium) | Win / macOS / Linux | 100M+ rows, "stream editing mode" for low-memory systems | full CSV editor with SQL-style filtering and built-in charts; the strongest commercial competitor for "big CSV + charts" |
| **Cassava** | commercial (beta) | macOS / Linux | millions of rows | editor with multi-file SQL, statistics, charts and pivots |
| **CsvTitan** | proprietary, local-first | Win / macOS / Linux | 10 GB+, larger than RAM; Rust | read / filter / SQL / regex / export; not DFIR-oriented |
| **CSView** | proprietary | macOS | 300M-row example; read-only | safe read-only viewing of giant CSVs — the "read-only huge viewer" niche is occupied |
| **Colomin** | AGPL-3.0 + commercial terms | Win / macOS / Linux | 10M+ rows; background indexing streams the file into view; Rust | a focused, fully offline CSV editor |
| **CEESVEE** | MIT | Win / macOS / Linux | multi-GB in bounded-memory read-only mode via a streaming record index; Tauri v2 + Rust core, React frontend receives only visible windows | local-first (no account, no cloud, no telemetry); charts and scripting are explicit v1 non-goals |
| **Tablecruncher** | GPL-3.0-or-later | Win / macOS / Linux | 2 GB / 16M rows opened in 32 s on an M2 Mac mini; C++17 + FLTK | lightweight native editor with JavaScript macros |
| **Columnar** | BSD-3-Clause | Win / macOS / Linux | tested to 14 GB / 28M rows; full per-row offset index (~8 B/row, ~225 MB, 20–30 s), mmap + Rayon | read-only viewer with statistics, search and sort |
| **Dinosaur** | MIT | Windows builds | tested to 170 GB; mmap + memchr + Rayon sparse *line* index, checkpoint every 4,096 lines; Rust / egui | read-only grid, search, go-to-row; line-oriented, so quoted multi-line fields are not records |
| **LeanRows** | MIT | Windows | 1.5 GB / 20M rows at 18.4 MB peak working set; quote-aware record boundaries across read blocks; no network by design | deliberately minimal read-only viewer; the closest precedent for the evidence-safe viewer part of gridsift |
| **Duckling** | MIT | Win / macOS / Linux | DuckDB + Arrow transport; Tauri 2 + React | SQL editor, pivots, column profiling for CSV / Parquet / JSON and databases |
| **Tad** | MIT | Win / macOS / Linux (Electron) | in-memory DuckDB; designed for millions of rows | hierarchical pivots and SQL-generated analysis |
| **OpenRefine** | BSD-style | local browser UI | server / client wrangling architecture; not a constant-memory raw-file viewer | strong transformations with a reproducible operation history — conceptually close to gridsift's manifest, far from its file engine |
| **LibreOffice Calc / Excel** | MPL-2.0 / proprietary | desktop | 1,048,576 rows (16M with LibreOffice's very-large-spreadsheet mode) | the baseline analysts fall back to; not applicable at the sizes above |

## Command-line and terminal tools

| Tool | License | Notes |
|---|---|---|
| **qsv** | MIT / Unlicense | the most capable CSV CLI suite: index-backed and streaming commands, regex, validation, statistics, offline GeoNames / MaxMind geocoding, visualisation output; a project-reported 15 GB / 28M-row count in ~12 s without an index. Batch-oriented; no interactive investigation view |
| **xan** | MIT | successor-in-spirit to xsv: fast, low-memory, parallel analysis CLI with an expression language |
| **xsv** | MIT / Unlicense | the original Rust CSV index / query CLI; archived, its README points to qsv and xan |
| **Miller (`mlr`)** | BSD-2-Clause | record-streaming transformations over CSV / TSV / JSON; the reference for constant-memory pipeline semantics |
| **csvkit** | MIT | Python CSV toolkit; its own documentation recommends SQL or qsv / xsv beyond moderate sizes |
| **q** | GPL-3.0 | SQL over CSV via SQLite; a 4.8 GB file takes minutes on first parse and seconds from its disk cache — the case for incremental caching |
| **VisiData** | GPL-3.0 | terminal spreadsheet with search, pivots, frequency tables; rows are held as Python objects, so single sheets of many millions of rows are memory-bound |
| **csvlens** | MIT | "less for CSV": navigation, search, filter and sort in the terminal; also an embeddable Rust library |
| **lazycsv** | OSS | memory-mapped lazy access, cell editing, DuckDB-backed SQL in a TUI |

## Engines and libraries

| Component | License | Relevance |
|---|---|---|
| **DuckDB** | MIT | out-of-core grouping, joining, sorting and window functions with disk spilling; the candidate engine for SQL over a selection in a later gridsift version |
| **Apache Arrow / Parquet** | Apache-2.0 | columnar in-memory and on-disk formats; a possible derived cache, with the source CSV remaining the authoritative evidence |
| **Rust `csv` crate** | Unlicense / MIT | the reference parser gridsift's scanner is checked against on torture and random input |
| **MaxMind DB format / `maxminddb` crate** | ISC (crate) | GeoLite2 / DB-IP Lite readers; databases are imported by the user, never bundled |
| **Public Suffix List / `psl` crate** | MPL-2.0 (list), MIT / Apache-2.0 (crate) | registrable-domain classification without any network access |
| **egui / eframe** | MIT / Apache-2.0 | immediate-mode GUI in pure Rust; a single-language, statically linked desktop binary |

## Capability matrix

`✓` documented in the reviewed material, `~` partial or adjacent, `—` not
found in the reviewed documentation (which does not prove absence).

| Capability | EmEditor | Modern CSV | CEESVEE | Colomin | qsv | LeanRows | gridsift |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Files larger than RAM | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Cross-platform | — | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Open source | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| Interactive GUI | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| Quote-aware records (multi-line fields) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Search / filter / value counts / time buckets in one view | ~ | ~ | ~ | ~ | — | — | ✓ |
| Nested selection steps shown and recorded | — | — | — | — | — | — | ✓ |
| Offline GeoIP / ASN | — | — | — | — | ✓ | — | ✓ |
| Domain classification (PSL) | — | — | — | — | ~ | — | ✓ |
| Semantic column typing (ip, hash, timestamp, …) | — | — | — | — | ~ | — | ✓ |
| Read-only evidence mode | ~ | ~ | ✓ | — | — | ✓ | ✓ |
| Source digest on open | — | — | — | — | ~ | — | ✓ |
| Provenance manifest for exports, with verification | — | — | — | — | — | — | ✓ |
| Export-time redaction with recorded policy | — | — | — | — | ~ | — | ✓ |
| No network by design | — | ~ | ✓ | ✓ | ✓ | ✓ | ✓ |
| In-place editing | ✓ | ✓ | ✓ | ✓ | — | — | — (by design) |
| SQL | ~ | ✓ | ~ | — | ~ | — | — (planned) |

## What gridsift takes from each

- **LeanRows, Dinosaur, Columnar** — bounded-memory navigation through a
  byte-offset index. gridsift's index is sparse (like Dinosaur's) but stores
  parser state at each checkpoint (like LeanRows' quote-aware boundaries),
  so quoted multi-line fields are records and scans can resume anywhere.
- **qsv** — the breadth of what a CSV CLI should do, `--json` everywhere,
  and offline geocoding as a first-class feature.
- **OpenRefine** — the idea that the operation history *is* the
  reproducibility story; gridsift makes it a manifest next to every export.
- **q** — the reminder that re-parsing a large CSV on every question is the
  wrong default: build the index once, keep it in a sidecar, reuse it.
- **CEESVEE / Colomin** — that "OSS + cross-platform + offline + large CSV"
  alone is not a differentiator; the investigation flow and the evidence
  model are.
