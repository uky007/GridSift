# gridsift

**An offline, evidence-safe workbench for investigating multi-gigabyte CSV
security data — without loading it into RAM, uploading it anywhere, or
modifying the source.**

> Status: pre-alpha. Phase 0 (core engine + CLI) is under construction.
> Target: Black Hat USA 2027 Arsenal / DEF CON Demo Labs.

## What it is

DFIR and threat-hunting teams routinely receive delimited exports — proxy
logs, EDR telemetry, firewall/netflow, authentication events — that are far
too large for a spreadsheet and too ad hoc for a SIEM. gridsift opens such
files *as they are*:

- **Bounded memory.** A 100 GB file is navigated through a sparse,
  quote-aware record index; resident memory does not grow with file size.
- **Immediate.** First rows appear before any full scan; indexing and hashing
  run in the same background pass.
- **Evidence-safe.** The source is opened read-only and never rewritten.
  Its SHA-256 is computed on open; every derived artefact is tied to it.
- **Strictly offline.** No telemetry, no update checks, no remote resources.
  Enrichment (GeoIP, domain classification, local lookups) uses only data
  packs the analyst imports.
- **Reproducible.** Filters, enrichments and exports are recorded in a
  provenance manifest so a finding can be regenerated from the same evidence.

## What it is not

Not a spreadsheet: no formulas, no cell formatting, no in-place editing of
evidence. Analyst changes live in a sidecar overlay and become a *new* file
only on export.

## Layout

```
crates/gridsift-core     engine: source, dialect sniffing, scanner, sparse index,
                         viewport reader, digests, synthetic data
crates/gridsift-cli      `gridsift` command-line tool (info / index / rows /
                         search / freq / export / verify / profile / count /
                         hash / gen)
crates/gridsift-desktop  `gridsift-desktop`, the egui application: open a file,
                         rows appear immediately, index + SHA-256 build in the
                         background, virtual grid with go-to-row, parallel
                         literal/regex search with highlight or filtered view,
                         value counts with click-to-filter, export with manifest
bench/                   benchmark procedure and baseline numbers
survey/                  background research the design is based on
```

## Building

Rust 1.85+ (edition 2024).

```
cargo build --release
./target/release/gridsift --help
```

Quick check on a synthetic 1 GB file:

```
gridsift gen  --profile narrow --size 1G -o /tmp/narrow-1g.csv
gridsift info /tmp/narrow-1g.csv            # dialect + first rows, no scan
gridsift index /tmp/narrow-1g.csv           # sparse index + SHA-256, one pass
gridsift rows  /tmp/narrow-1g.csv --start 3000000 --count 5
gridsift search /tmp/narrow-1g.csv '/c2/beacon' -c host -n 5     # literal, one column
gridsift search /tmp/narrow-1g.csv -r 'deny,"curl/[0-9.]+"'      # regex, all cores
gridsift export /tmp/narrow-1g.csv -o beacon.csv -s '/c2/beacon' -c path
gridsift verify beacon.csv                  # re-hashes output and source against the manifest
gridsift profile /tmp/narrow-1g.csv         # what each column holds: ipv4, domain, sha256, …
gridsift freq /tmp/narrow-1g.csv -c host -n 20               # top hosts over all records
gridsift freq /tmp/narrow-1g.csv -c dst_port -s ',deny,'     # …over the records matching a search
gridsift-desktop /tmp/narrow-1g.csv         # or drag & drop onto the window
gridsift-desktop /tmp/narrow-1g.csv --search '/c2/beacon' --filter
```

`export` writes the selected records as their exact source bytes (quoting
preserved, terminators normalised) to a new file, atomically, and puts a
provenance manifest next to it — `beacon.csv.manifest.json` — recording the
source identity (size, mtime, SHA-256), the parser settings, the query that
produced the selection, and the output's own SHA-256. It refuses to write
onto the source. `verify` recomputes both digests.

The desktop app and the CLI share the index sidecar (stored under the user
cache directory, never next to the evidence), so a file indexed by one opens
instantly in the other.

## Value counts

`freq` (and the desktop "Count values of" panel) counts the values of one
column over all records or over a search's matches, on all cores. Counting
is exact up to 131,072 distinct values per worker; beyond that it switches
to lossy counting so memory stays bounded on high-cardinality columns
(hashes, unique IDs), and the result then says so and gives an error bound.
Distinct values are counted exactly when possible and estimated with
HyperLogLog otherwise. In the desktop app, clicking a value filters the grid
by it — the pivot step of an investigation.

## Semantic typing

`profile` (and the desktop grid header) labels each column with what it
appears to hold — `timestamp`, `ipv4`, `ipv6`, `ip:port`, `mac`, `domain`,
`url`, `email`, `md5`/`sha1`/`sha256`, `uuid`, `port`, `http_status`,
`integer`, `float`, `boolean`, `categorical`, `text` — from a sample drawn
from the head of the file and from positions spread across it. The label
comes with its evidence (share of sampled values, distinct count, examples)
and is an annotation only: values are never converted.

## Correctness model

Record boundaries are found by a quote-aware scanner that follows the
`csv` crate's lenient rules (quoted fields may contain delimiters, quotes as
`""`, and newlines; `\n`, `\r`, `\r\n` all terminate records; empty lines are
skipped). The scanner and field splitter are checked against the `csv` crate
on a torture corpus and on randomly generated input (`cargo test`).

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
