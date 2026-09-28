# gridsift

[![CI](https://github.com/uky007/GridSift/actions/workflows/ci.yml/badge.svg)](https://github.com/uky007/GridSift/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

An offline, evidence-safe workbench for investigating multi-gigabyte CSV
security data — without loading it into RAM, uploading it anywhere, or
modifying the source. Written in Rust; command-line tool and desktop
application for Linux, macOS and Windows.

> Status: pre-release, under active development. Interfaces and the
> manifest format may still change before 1.0.

## Concept

- **Evidence-safe** -- The source is opened read-only and never rewritten.
  Its SHA-256 is computed on open; every derived artefact is tied to it.
- **Bounded memory** -- A sparse, quote-aware record index (a few KiB per
  GiB) is all that is kept. A 10 GiB file is navigated with ~10 MiB of RSS.
- **Strictly offline** -- No telemetry, no update checks, no DNS.
  Enrichment (GeoIP / ASN, domain classification, lookups) uses only local
  datasets the analyst imports, each identified by hash.
- **Reproducible** -- Every filter, time range, enrichment and redaction is
  recorded in a provenance manifest next to the export; `gridsift verify`
  checks it later.

## Interfaces

| Interface | Binary | Description |
|-----------|--------|-------------|
| **CLI** | `gridsift` | Index, search, count, timeline, profile, export, verify; `--json` on every command for scripting and batch use. |
| **Desktop** | `gridsift-desktop` | The interactive investigation: instant rows, search and pivot with a visible selection lineage, timeline and value counts, enrichment, export with redaction. |

## Quick install

Rust 1.85 or newer. Not on crates.io yet — build from source:

```
git clone https://github.com/uky007/GridSift.git
cd GridSift
cargo build --release
./target/release/gridsift --help
./target/release/gridsift-desktop
```

See [docs/installation.md](docs/installation.md) for Linux build
dependencies, the `dist` profile and where the index cache lives.

## Quick usage

```
gridsift gen  --profile narrow --size 1G -o proxy.csv   # synthetic proxy log, seed 1
gridsift info proxy.csv                                  # dialect + first rows, no scan
gridsift index proxy.csv                                 # sparse index + SHA-256, one pass
gridsift search proxy.csv '/c2/beacon' -c path -n 5      # literal, one column, all cores
gridsift search proxy.csv -r 'deny,"curl/[0-9.]+"'       # regex
gridsift freq proxy.csv -c dst_port -s '/c2/beacon'      # top values over the matches
gridsift timeline proxy.csv -c timestamp -b 1h           # records per hour
gridsift profile proxy.csv                               # ipv4, domain, sha256, timestamp, …
gridsift export proxy.csv -o beacon.csv -s '/c2/beacon' -c path \
    --redact user=hmac --redact user_agent=drop --domain host --hmac-key-file key.txt
gridsift verify beacon.csv                               # re-hash output and source against the manifest
```

```
gridsift-desktop proxy.csv                               # or drag & drop onto the window
gridsift-desktop proxy.csv --search '/c2/beacon' --timeline
```

See [docs/usage.md](docs/usage.md) for every option, `jq` recipes and the
desktop walkthrough.

## Key features

- **Instant open** -- rows on screen in milliseconds; the index and the
  SHA-256 are built in one background pass (~1 s per GiB warm).
- **Quote-aware sparse index** -- checkpoints carry parser state, so
  multi-line quoted fields are records, any record is one bounded read
  away, and scans run on all cores over disjoint ranges.
- **Search** -- literal and regex, per column, case-insensitive, inverted;
  2–13 GiB/s on a laptop; results are a compressed bitmap of records.
- **Selection lineage** -- a search within a search within a time range:
  each step is a chip with its count, revertable without rescanning, and
  exactly what the manifest records.
- **Value counts and timeline** -- top-N per column (exact, then lossy with
  a stated bound), records per time bucket with drag-to-select ranges.
- **Semantic typing** -- columns labelled ipv4, domain, sha256, timestamp,
  port, … with confidence; annotations only, values are never converted.
- **Offline enrichment** -- GeoIP / ASN from an imported MMDB, registrable
  domain from the bundled Public Suffix List, joins against local CSVs;
  derived columns in the grid, in counts and in exports.
- **Export with redaction** -- exact source bytes per record, or drop /
  mask / partial / ip-prefix / HMAC-pseudonymised columns; the policy (never
  the key) goes into the manifest.
- **Provenance manifest** -- source identity, parser settings, every
  operation, output digest ([docs/manifest.md](docs/manifest.md)).
- **Honest numbers** -- elapsed time, throughput and peak RSS on every
  command; approximate results say so.

## Screenshots

### Desktop: search, lineage, timeline

![gridsift desktop](images/gridsift-desktop.png)

### Value counts within the selection

![gridsift values](images/gridsift-values.png)

### Export finding: lineage, redaction, manifest

![gridsift export](images/gridsift-export.png)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (input not found or unreadable, invalid arguments) — for `verify`, a digest mismatch |

## Docs

- [Description & feature list](docs/description.md)
- [Installation](docs/installation.md)
- [Usage & examples](docs/usage.md)
- [The provenance manifest](docs/manifest.md)
- [Survey of existing tools](docs/survey.md)
- [Roadmap](docs/roadmap.md)
- [Desktop UI design](docs/design/README.md)
- [Benchmarks](bench/README.md)

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party licences are listed in [NOTICE](NOTICE).
