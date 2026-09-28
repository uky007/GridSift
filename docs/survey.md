# Survey of existing tools

> **Status note (checked 2026-09-28).** Every entry below was checked
> against the project's own README, documentation or product page on that
> date; the page used is listed in [References](#references). Size and
> speed figures are the projects' own claims, measured on their hardware
> and data — they are not comparable with each other or with gridsift's
> numbers. "Not documented" means the reviewed pages do not say; it does
> not prove absence. Prices and editions change; treat them as
> indicative.

## Scope and method

The question was: *what does a DFIR analyst, threat hunter or forensic
examiner use today to look at a multi-gigabyte CSV/TSV export on a
workstation — often offline — and what does each option cost them in
size, interactivity, evidence handling and network exposure?* (The case
for the tool is in [motivation.md](motivation.md).)

Four families were reviewed:

1. **DFIR-native tools** that produce or consume large CSV timelines.
2. **Large-file viewers and editors** — the applications that open files
   spreadsheets cannot.
3. **Command-line CSV tools and engines.**
4. **Ingest-and-index platforms** (SIEM / search stacks) as the
   "load it somewhere" alternative.

For each tool the reviewed pages were read for: licence and platforms; the
documented approach to large input (in memory, streamed, indexed, copied
into a store); whether quoted multi-line fields are handled as records;
offline / no-network statements; and any provenance features (source
hashes, operation logs, export manifests).

## 1. DFIR-native tools

| Tool | Licence · platforms | Large input | Offline · provenance | Position |
|---|---|---|---|---|
| **Timeline Explorer** (Eric Zimmerman) | free download, source not public; Windows (.NET 9) | filtering, searching, sorting, grouping; no memory model or size guidance documented | local desktop app; no provenance features documented | the de-facto viewer for KAPE / EZ-tool and Hayabusa CSV output; Windows-only |
| **Timesketch** | Apache-2.0; Docker on Ubuntu, ≥ 8 GB RAM | CSV/JSONL imported into OpenSearch (importer splits large files); "hundreds of millions of events" with a multi-node cluster | can run on an isolated host, but it is a server stack (web, worker, PostgreSQL, OpenSearch, Redis); no source hashing documented | collaborative timeline platform; the data is copied into an index |
| **Plaso** (log2timeline / psort) | Apache-2.0; macOS, Linux, Windows | *produces* timelines: `.plaso` storage, then `psort` to CSV (`l2tcsv`, `dynamic`), JSON, XLSX, OpenSearch | `pinfo` records command line, tool version, parsers; optional `--hashers` stores hashes of processed files | upstream of gridsift: it makes the multi-GB CSVs that then need a viewer |
| **Velociraptor** | AGPL-3.0; Windows, Linux, macOS | VQL `parse_csv` streams rows; notebooks with VQL cells; "Instant Velociraptor" runs server + client on loopback in a browser | offline collector produces encrypted zips; local mode still needs a browser and a datastore | a full endpoint-collection platform; CSV analysis is scripted VQL, not a bounded-memory grid |
| **Zui** (formerly Brim) | licence not stated in the repository; Windows, macOS, Linux (Electron) | data is loaded into a local Zed/SuperDB lake; inputs include pcap (via Brimcap), Zeek logs, JSON, Parquet, CSV | no provenance documented; latest release Sept 2024 | pcap / Zeek-centric; CSV is an ingest format, and the app works on the copy |
| **Hayabusa, Chainsaw, Takajo** | AGPL-3.0 / GPL-3.0 / AGPL-3.0 | EVTX analysers that *emit* CSV / JSONL timelines; Hayabusa's README recommends "LibreOffice, Timeline Explorer, Elastic Stack, Timesketch and more" as viewers | — | producers, not viewers; their output is a gridsift input |

What this family shows: the DFIR ecosystem has excellent *producers* of
large CSV timelines and one widely used *viewer* — free, Windows-only,
with nothing documented about scale or provenance. Everything larger goes
into a server-side index.

## 2. Large-file viewers and editors

| Tool | Licence · platforms | Large input (project's own claim) | Offline · provenance | Position |
|---|---|---|---|---|
| **EmEditor** | proprietary; Free (personal use only, no CSV tools) / Professional subscription; Windows | "up to 16 TB or 1,099 billion lines" using temporary files; vendor benchmark: open a 10 GB file in 1.067 s, sort it in 7.271 s; the CSV mode handles newlines embedded in cells and offers filter, sort, join and pivot tables | "privacy-first" listed without detail; no hashing | the performance reference for huge text and CSV editing |
| **Modern CSV** (v3 beta) | proprietary freemium; Windows, macOS, Linux | v3 beta: "more than 100 million rows", "Stream Editing Mode for ultra-large files on low-memory systems"; read-only mode with "a small memory footprint" | "Your data remains local. It's never sent to the cloud"; no hashing | editor with charts and Python plugins (beta build expires 2026-12-31) |
| **CEESVEE** | MIT; Windows, macOS, Linux (Tauri v2, Rust core, React UI) | "Multi-GB files open read-only against a streaming record index … with bounded memory"; 1M rows / 100 MB+ is "a core requirement" | "no telemetry, no analytics, and no network calls"; exports can write "a JSON manifest recording row counts and SHA-256 hashes" | the closest OSS editor in spirit; charts and scripting are v1 non-goals |
| **LeanRows** | MIT; Windows x64 | "20,000,001 rows, 1,532,454,643 bytes, fully indexed. Peak working set: 18.4 MB"; record boundaries "quote-aware across read blocks, including quoted fields containing newlines" | "no telemetry and no network access of any kind" | read-only viewer; the closest precedent for the evidence-safe viewer part of gridsift |
| **Columnar** | BSD-3-Clause; Windows, macOS, Linux (Tauri v2) | "tested up to 28 million rows and 14 GB"; byte offset of every row (~225 MB index for 28M rows, 20–30 s to build); memory ≈ rows × 8 B | not documented | read-only viewer with statistics, search, sort |
| **Colomin** | AGPL-3.0-or-later + commercial terms; macOS, Linux, Windows (Rust / egui) | "10M+ rows"; "Background indexing streams huge files into view" | "No cloud, no subscription … Your data stays on your machine" | a focused CSV *editor* |
| **Tablecruncher** | GPL-3.0-or-later; macOS, Windows, Linux (C++17 / FLTK) | "a 2 GB file with 16 million rows … in just 32 seconds" on a Mac mini M2 | not documented | lightweight editor with JavaScript macros |
| **CsvTitan** | proprietary; Windows, macOS, Linux (Rust) | "Open 10GB+ CSVs instantly without loading bars or memory crashes" | "A strictly local CSV viewer. No data egress, no cloud uploads" | viewer with filter / query / export |
| **CSView 2** (and CSView 1.x) | 2: proprietary, macOS; 1.x: Apache-2.0, macOS / Windows / Linux | 2: "A 27 GB synthetic dataset with over 300M rows" scrollable "within seconds"; 1.x: "files larger than 4GB" | "No subscriptions, no cloud, no telemetry"; "never modifies your source data" | read-only viewer |
| **LogViewPlus** | commercial; Windows (.NET Framework 4.8) | "constrained only by the amount of system memory"; "500 MB log file in about 30 seconds"; chunking for larger files | not documented | in-memory log viewer with a DSV parser (quoted multi-line fields) |
| **klogg** / glogg | GPL-3.0(+); Windows, macOS, Linux (Qt) | "reads the file directly from disk, without loading it into memory"; "10+ Gb is not a problem"; > 2^31 lines | not documented | line-oriented regex log viewer; no columns, types or time buckets |
| **lnav** | BSD-2-Clause; Linux, macOS, Windows | "No server. No setup"; CSV/TSV via a `tabular` format declaration; SQLite queries | not documented | terminal log navigator |
| **Tad** | MIT; macOS, Linux, Windows (Electron) | CSV imported into an in-memory DuckDB instance; "supports large files" without figures | not documented | pivot-table viewer; author describes it as a hobby project |
| **Duckling** | MIT; Windows, macOS, Linux (Tauri 2) | DuckDB + Arrow transport; no size claim | not documented | viewer for CSV / Parquet and databases |
| **Thoth** | MIT; macOS, Windows, Linux (Rust / egui) | "gigabyte-sized" JSON / NDJSON, parsed lazily; CSV via a bundled plugin | plugins are sandboxed WebAssembly components (Wasmtime) | JSON-centric data workspace; interesting plugin model |
| **lazycsv** | MIT; macOS, Linux, Windows (Rust TUI) | "Open a 10GB file instantly", memory-mapped; DuckDB-backed queries including UPDATE / DELETE; cell editing | not documented | terminal editor |
| **Cassava** | commercial, release candidate; macOS, Linux | "millions of rows"; multi-file SQL, charts, pivots | not documented | editor |
| **OpenRefine** | BSD-3-Clause; Windows, macOS, Linux (local web app) | "large" defined as > 1M cells or > 50 MB; default 1 GB heap | "does not require internet access"; "Infinite undo/redo … replay your operation history on a new version" | data cleaning; the operation-history idea is the closest cousin of gridsift's manifest |
| **Excel / LibreOffice Calc** | proprietary / MPL-2.0 | 1,048,576 rows × 16,384 columns per sheet | — | the baseline analysts fall back to |

What this family shows: bounded-memory viewing of huge files exists —
line-oriented (klogg, EmEditor) or CSV-aware (LeanRows, CEESVEE, Columnar,
CSView) — and several products now state "no cloud / no telemetry".
Provenance is almost absent: CEESVEE's export manifest (row counts and
SHA-256 of outputs) is the only such feature found among viewers and
editors, and no viewer documents hashing the *source* on open. None
combines search, value counts and a time histogram over a recorded
selection.

## 3. Command-line tools and engines

| Tool | Licence · platforms | Large input | Offline · provenance | Position |
|---|---|---|---|---|
| **qsv** | MIT; Linux, macOS, Windows | streaming and index-backed commands; "11.87 seconds for a 15gb, 28m row NYC 311 dataset without an index. Instantaneous with an index" | offline geocoding "against an updatable local copy of the Geonames cities & the Maxmind GeoLite2 databases"; "Compute or check BLAKE3 hashes of files"; `fetch` and `--update` do use the network | the most capable CSV CLI suite; the reference for what a CSV tool should be able to do |
| **xan** | Unlicense OR MIT; macOS, Linux, Windows | "large CSV files (gigabytes to terabytes)" | not documented | analysis CLI with an expression language; rewritten fork of xsv |
| **xsv** | MIT OR Unlicense | born from "a 40GB CSV file"; index for constant-time positioning | — | archived April 2025; README recommends qsv or xan |
| **Miller** (`mlr`) | BSD-2-Clause; Linux, macOS, Windows | "streaming: most operations need only a single record in memory" | not documented | record-streaming transformations |
| **csvkit** | MIT; Python | docs: "If you need csvkit to be faster or to handle larger files … Consider loading the data into SQL, or using qsv or xsv" | not documented | conversion utilities |
| **q** | GPL-3.0; macOS, Linux, Windows | 5M rows × 100 columns (4.8 GB): 4 min 47 s uncached vs 1.92 s with its disk cache | not documented | SQL over CSV via SQLite; the case for building an index once and reusing it |
| **VisiData** | GPL-3.0; Linux, macOS, Windows (WSL) | loaders stream rows, but a loaded sheet is held in memory | command log (`.vdj`) records and replays a session | terminal exploration; the command log is a reproducibility feature worth noting |
| **csvlens** | MIT; macOS, Linux, BSDs, Windows | not documented | not documented | "like less but made for CSV" |
| **DuckDB** (CLI) | MIT; single static binary for Windows, macOS, Linux | `read_csv` sniffs dialect and types, reads in parallel, keeps rejected lines; GROUP BY / JOIN / ORDER BY / window spill to disk, with documented out-of-memory caveats; `-readonly` | engine is offline; the optional UI extension fetches its front end from a remote server; no provenance features | the natural engine for SQL over a selection; not a workbench and not evidence-aware |

## 4. Ingest-and-index platforms

| Platform | What a one-off export costs |
|---|---|
| **Splunk Free** | indexes "500 MB per day"; search is blocked after three licence warnings in 30 days; reference production hardware is 12 physical cores / 12 GB RAM / 800 IOPS. A 20 GB export exceeds the daily cap forty times over |
| **Elastic / Kibana** | Elasticsearch and Kibana servers plus an ingest path (Agent, Beats, Logstash or pipelines); Kibana's file upload is capped at 500 MB by default, 1 GB at most |
| **Timesketch** | the Docker stack above; CSV needs `message`, `datetime`, `timestamp_desc` columns; OpenSearch keyword fields are capped at 32,766 bytes |

All three copy the evidence into an index, need server processes and
indexing time, and are the right answer when the infrastructure already
exists and the data will be revisited by a team. For triage of one export
on one laptop — the situation in [motivation.md](motivation.md) — they
are heavy, and the copy they create is not the evidence.

## Capability matrix

`✓` documented in the reviewed material · `~` partial or adjacent · `—`
not found in the reviewed documentation (which does not prove absence).
The gridsift column is self-reported and describes what is implemented
today.

| Capability | Timeline Explorer | EmEditor | Modern CSV | CEESVEE | LeanRows | klogg | qsv | DuckDB CLI | Timesketch | gridsift |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Files larger than RAM | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (server) | ✓ |
| Quoted multi-line fields are records | ✓ | ✓ | ✓ | ~ | ✓ | — | ✓ | ✓ | ~ | ✓ |
| Interactive GUI | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ (web) | ✓ |
| Cross-platform | — | — | ✓ | ✓ | — | ✓ | ✓ | ✓ | ~ | ✓ |
| Open source | — | — | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Search + value counts + time buckets over the same selection | ~ | ~ | ~ | ~ | — | ~ | ~ | ~ (SQL) | ✓ | ✓ |
| Selection steps shown and recorded | — | — | — | — | — | — | — | — | — | ✓ |
| No network by design (documented) | — | — | ~ | ✓ | ✓ | — | ~ | ~ | — | ✓ |
| Source hashed on open | — | — | — | — | — | — | ~ (command) | — | — | ✓ |
| Provenance manifest on export, verifiable later | — | — | — | ~ | — | — | — | — | — | ✓ |
| Offline GeoIP / ASN and domain enrichment | — | — | — | — | — | — | ✓ | — | — | ✓ |
| Export-time redaction with recorded policy | — | — | — | — | — | — | — | — | — | ✓ |
| Semantic column typing (ip, hash, timestamp, …) | — | — | — | ~ | — | — | ~ | ~ | — | ✓ |
| In-place editing | — | ✓ | ✓ | ✓ | — | — | — | — | — | — (by design) |
| SQL | — | — | — | — | — | — | ~ | ✓ | ~ | — (planned) |

Reading the matrix by column: the tools that keep memory bounded are
viewers, editors or engines without an evidence model; the tools with a
reproducibility feature (CEESVEE's export manifest, OpenRefine's operation
history, VisiData's command log, Plaso's extraction metadata) do not
combine it with bounded-memory interactive investigation. No reviewed
tool hashes the source on open and ties every subsequent step to it.

## What gridsift takes from each

- **LeanRows, Columnar, CSView, klogg** — bounded-memory navigation
  through a byte-offset index. gridsift's index is sparse (checkpoints
  rather than every row) and stores parser state at each checkpoint, so
  quoted multi-line fields are records and a scan can resume anywhere on
  any core.
- **CEESVEE** — the export manifest with SHA-256 digests. gridsift starts
  earlier (the *source* is hashed on open) and records every step between
  source and output, then verifies both ends.
- **qsv** — the breadth of a CSV CLI, `--json` on every command, and
  offline geocoding as a first-class feature.
- **OpenRefine, VisiData** — that the operation history *is* the
  reproducibility story; gridsift makes it a manifest next to every export
  and shows it on screen as the selection lineage.
- **q** — that re-parsing a large CSV for every question is the wrong
  default: build the index once, keep it in a sidecar, reuse it.
- **Plaso, Hayabusa, Chainsaw, Velociraptor** — the producers whose
  output gridsift is meant to open; their column conventions
  (`datetime`, `timestamp_desc`, `message`) are the first thing the
  semantic typer should recognise.
- **DuckDB** — the engine gridsift intends to embed for SQL over a
  selection, keeping the source CSV authoritative.
- **Thoth** — a capability-limited WebAssembly plugin model, if gridsift
  ever grows extensions.

## References

Pages consulted on 2026-09-28.

**DFIR-native**
- Timeline Explorer — https://ericzimmerman.github.io/ ; third-party scale note: https://dfirmadness.com/case-001-super-timeline-analysis/
- Timesketch — https://github.com/google/timesketch ; https://timesketch.org/guides/admin/install/ ; https://timesketch.org/guides/user/import-from-json-csv/ ; https://timesketch.org/guides/admin/scaling-and-limits/
- Plaso — https://github.com/log2timeline/plaso ; https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html ; https://plaso.readthedocs.io/en/latest/sources/user/Using-pinfo.html
- Velociraptor — https://github.com/Velocidex/velociraptor ; https://docs.velociraptor.app/docs/deployment/ ; https://docs.velociraptor.app/vql_reference/parsers/ ; https://docs.velociraptor.app/docs/deployment/offline_collections/
- Zui — https://github.com/brimdata/zui ; https://zui.brimdata.io/docs/support/Supported-Platforms
- Hayabusa — https://github.com/Yamato-Security/hayabusa ; Takajo — https://github.com/Yamato-Security/takajo ; Chainsaw — https://github.com/WithSecureLabs/chainsaw

**Viewers and editors**
- EmEditor — https://www.emeditor.com/ ; https://www.emeditor.com/text-editor-features/emeditor-free/ ; CSV features (embedded newlines, pivot) — https://www.emeditor.com/text-editor-features/more-features/csv-tsv-dsv/ ; https://www.emeditor.com/faq/csv-faq/how-do-you-remove-embedded-newlines-in-a-csv-document/
- Modern CSV — https://www.moderncsv.com/ ; https://www.moderncsv.com/v3-beta/
- CEESVEE — https://github.com/soldforaloss/ceesvee ; https://ceesvee.com/
- LeanRows — https://github.com/abooodbah/leanrows
- Columnar — https://github.com/chdwql/Columnar
- Colomin — https://colomin.app/ ; https://github.com/saman/colomin
- Tablecruncher — https://github.com/Tablecruncher/tablecruncher ; https://tablecruncher.com/
- CsvTitan — https://csvtitan.com/
- CSView — https://kothar.net/csview ; https://github.com/csview-app/csview
- LogViewPlus — https://www.logviewplus.com/large-log-files.html ; https://www.logviewplus.com/docs/dsv_parser.html
- klogg — https://klogg.filimonov.dev/ ; https://github.com/variar/klogg ; glogg — https://github.com/nickbnf/glogg
- lnav — https://github.com/tstack/lnav ; https://docs.lnav.org/en/latest/formats.html
- Tad — https://www.tadviewer.com/ ; https://github.com/antonycourtney/tad
- Duckling — https://github.com/l1xnan/duckling
- Thoth — https://github.com/anitnilay20/thoth
- lazycsv — https://github.com/funkybooboo/lazycsv
- Cassava — https://cassava.dev/
- OpenRefine — https://openrefine.org/ ; https://openrefine.org/docs/manual/installing
- Excel — https://support.microsoft.com/en-us/office/excel-specifications-and-limits-1672b34d-7043-467e-8e27-269d656771c3 ; LibreOffice Calc — https://books.libreoffice.org/en/CG24/CG2401-Introduction.html

**Command-line tools and engines**
- qsv — https://github.com/dathere/qsv
- xan — https://github.com/medialab/xan
- xsv — https://github.com/BurntSushi/xsv
- Miller — https://github.com/johnkerl/miller
- csvkit — https://github.com/wireservice/csvkit ; https://csvkit.readthedocs.io/en/latest/
- q — https://github.com/harelba/q ; https://harelba.github.io/q/
- VisiData — https://github.com/saulpw/visidata ; https://www.visidata.org/docs/save-restore/ ; https://www.visidata.org/docs/api/loaders
- csvlens — https://github.com/YS-L/csvlens
- DuckDB — https://github.com/duckdb/duckdb ; https://duckdb.org/docs/current/data/csv/overview.html ; https://duckdb.org/docs/current/guides/performance/how_to_tune_workloads.html ; https://duckdb.org/docs/current/core_extensions/ui.html

**Platforms**
- Splunk Free — https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configure-splunk-licenses/about-splunk-free ; reference hardware — https://help.splunk.com/en/splunk-enterprise/get-started/deployment-capacity-manual/10.0/performance-reference/reference-hardware
- Elastic — https://www.elastic.co/subscriptions ; https://www.elastic.co/docs/get-started/the-stack ; Kibana upload limit — https://www.elastic.co/docs/reference/kibana/advanced-settings
