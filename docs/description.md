# gridsift — description and feature list

## Motivation

DFIR and threat-hunting teams routinely receive delimited exports — proxy
logs, EDR telemetry, firewall and netflow records, authentication events,
SIEM search results — as CSV files of one to a hundred gigabytes. They are
far too large for a spreadsheet and too ad hoc for a SIEM ingest, and they
are *evidence*: they must not be modified, and findings drawn from them
must be reproducible.

gridsift opens such a file *as it is*, with bounded memory, shows rows
immediately, hashes the file in the background, and keeps every step of
the investigation — search, time range, enrichment, redaction — in a
provenance manifest attached to what is exported. It never modifies the
source and never touches the network.

The full case — the situation, who the tool is for, how it is used and why
existing tools did not close the gap — is in [motivation.md](motivation.md);
the comparison with existing tools is in [survey.md](survey.md).

## Concept

- **Evidence-safe.** The source is opened read-only and never rewritten.
  Its SHA-256 is computed on open; every derived artefact is tied to it.
- **Bounded memory.** A sparse, quote-aware record index (a few KiB per GiB
  of source) is all that is kept; resident memory does not grow with file
  size. A 10 GiB file is navigated with ~10 MiB of RSS.
- **Strictly offline.** No telemetry, no update checks, no DNS. Enrichment
  uses only datasets the analyst imports, each identified by hash.
- **Reproducible.** Filters, enrichments and redactions are recorded in a
  manifest so a finding can be regenerated from the same evidence and
  verified later.
- **Honest numbers.** Approximate results (lossy counts, estimated
  cardinalities, sampled profiles) say so and give their bounds.

## Features

| Feature | Description |
|---|---|
| Dialect sniffing | Delimiter, quoting and header detection from the head of the file; every setting can be overridden and is recorded in the manifest |
| Quote-aware sparse index | Checkpoints every 4,096 records / 4 MiB with the parser state, so any record can be located by ordinal with one bounded read; index sidecars live in the user cache directory, never next to the evidence |
| Instant first rows | A bootstrap index shows rows before any full scan; the full index and the SHA-256 are built in one background pass |
| Digests | SHA-256 (default) and BLAKE3 of the source, computed on a separate thread from the scan |
| Search | Literal (memchr/memmem) and regex search over whole records or chosen columns, case-insensitive and inverted variants, on all cores; results are a compressed bitmap of record ordinals |
| Selection lineage | Steps nest: a search within a search, a time range within that. The chain is shown as chips in the desktop application and written to the manifest |
| Value counts | Top-N of a column over all records or the current selection; exact up to 131,072 distinct values per worker, then lossy counting with a stated error bound; distinct count exact or HyperLogLog-estimated |
| Timeline | Timestamp parsing (ISO 8601 / RFC 3339, `YYYY/MM/DD`, Apache CLF, syslog, US-style, Unix epoch s/ms/µs), per-bucket counts with automatic coarsening; interactive range selection in the desktop application |
| Semantic typing | Columns labelled as timestamp, ipv4/ipv6, ip:port, mac, domain, url, email, md5/sha1/sha256, uuid, port, http_status, integer, float, boolean, categorical or text, with confidence, from a sample across the file; annotations only, values are never converted |
| Offline enrichment | GeoIP / ASN from an imported MMDB, registrable domain / public suffix / subdomain from the bundled Public Suffix List, joins against local CSV lookup tables; derived columns appear in the grid, in counts and in exports |
| Export | Selected records written as their exact source bytes (or redacted / enriched variants) to a new file, atomically, with a provenance manifest next to it |
| Redaction | Per-column drop, mask, partial, IP-prefix and HMAC pseudonymisation; untouched columns keep their bytes; the policy — never the key — goes into the manifest |
| Verification | `gridsift verify` re-hashes the output and the source against the manifest |
| Synthetic data | `gridsift gen` produces deterministic datasets (narrow, wide, quotes, ragged profiles) of any size, so benchmarks are reproducible by hash |
| Two interfaces | A command-line tool for batch and scripted use (`--json` on every command) and a desktop application for the interactive investigation |

## Correctness model

Record boundaries are found by a quote-aware scanner that follows the `csv`
crate's lenient rules: quoted fields may contain delimiters, quotes as `""`
and newlines; `\n`, `\r` and `\r\n` all terminate records; empty lines are
skipped. Malformed input — a stray quote, an unterminated quoted field, a
row with the wrong number of fields — is counted and reported, never
"fixed". The scanner and the field splitter are checked against the `csv`
crate on a torture corpus and on randomly generated input, and the record
count of a 100 MiB torture file matches Python's `csv` module.

The index stores parser state at every checkpoint, so a scan can be resumed
from any checkpoint with the same result as a scan from the start. That is
what lets searches and counts run on all cores over disjoint ranges of the
file.

## Known limitations

- **Encodings.** Input is treated as bytes; UTF-8 is assumed for display and
  regex matching, and invalid sequences are shown lossily. UTF-16 files are
  not yet transcoded.
- **Compressed input.** `.gz` / `.zip` sources must be decompressed first.
- **Sorting and joins across the whole file** are not implemented; an
  out-of-core SQL engine (DuckDB) is a candidate for a later version.
- **Editing.** There is no in-place editing by design. Analyst annotations
  (tags, notes) are planned as a sidecar overlay that becomes a new file
  only on export.
- **Manifests are not signed.** They are plain JSON; integrity of the
  manifest itself relies on the case's own evidence handling.
- **Timestamps without a time zone** are taken as UTC; a per-file offset is
  not yet configurable.
- **GeoIP** has been tested with a mock provider and the `maxminddb` crate's
  test databases; real-world GeoLite2 files are read through the same path
  but have not been benchmarked.
- **Scale validation.** Measurements so far cover 1–10 GiB files on a
  32 GB machine with a warm page cache (see [../bench/README.md](../bench/README.md));
  the 100 GB cold-cache run is planned.
