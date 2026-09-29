# Usage

## Command line

Every command accepts `--json` for machine-readable output and prints
elapsed time, throughput and peak RSS. Dialect overrides (`-d ,` / `-d tab`,
`--no-quote`, `--header` / `--no-header`) are accepted wherever a file is
read. The index sidecar is found in the user cache directory automatically;
`--index PATH` uses another one.

```
gridsift info    FILE                     # dialect + first rows, no scan
gridsift index   FILE                     # sparse index + SHA-256 in one pass
gridsift rows    FILE -s 3000000 -n 5     # records by ordinal (0-based, header excluded)
gridsift search  FILE '/c2/beacon' -c path -n 5          # literal, one column
gridsift search  FILE -r 'deny,"curl/[0-9.]+"'           # regex, all cores
gridsift search  FILE 10.0.0.1 -c src_ip --exact         # whole field only: not 10.0.0.10
gridsift search  FILE allow -v                           # records that do NOT match
gridsift freq    FILE -c host -n 20                      # top hosts over all records
gridsift freq    FILE -c dst_port -s ',deny,'            # …over the records matching a search
gridsift timeline FILE -c timestamp                      # auto bucket width
gridsift timeline FILE -c timestamp -b 1h -s deny        # hourly, over matches
gridsift profile FILE                                    # what each column holds
gridsift export  FILE -o beacon.csv -s '/c2/beacon' -c path
gridsift verify  beacon.csv                              # re-hash output and source
gridsift count   FILE                                    # full quote-aware scan, no index
gridsift hash    FILE                                    # SHA-256 + BLAKE3
gridsift gen     --profile narrow --size 10G -o narrow-10g.csv   # synthetic data, seed 1
```

### Commands

| command | what it does |
|---|---|
| `info` | Sniff the dialect and show the first records without scanning the file |
| `index` | Build the sparse record index and the source digest in one pass (`--hash sha256\|blake3\|all\|none`, `--stride-records`, `--stride-bytes`, `--index PATH`) |
| `rows` | Print records by ordinal using the index (`-s START -n COUNT`, `--raw` for the exact bytes) |
| `search` | Literal, regex (`-r`) or exact-field (`--exact`) search; `-i` case-insensitive, `-c COLUMN` (repeatable), `-v` invert, `-n` records to print, `--threads`. `--exact` selects records where the whole field equals the pattern (`10.0.0.1` does not select `10.0.0.10`); it is what a value-count pivot uses, and the `-s` searches of `freq`, `timeline` and `export` accept it too |
| `freq` | Count the values of one column, top-N, over all records or a search's matches; enrichment options add derived columns to count |
| `timeline` | Count records per time bucket of a timestamp column (`-b auto\|30s\|5m\|1h\|1d`, `--year` for syslog timestamps) |
| `profile` | Detect what each column holds from a sample across the file |
| `export` | Write all records, a `--range START:COUNT`, or a search's matches to a new file with a manifest; `--redact`, `--geoip`, `--domain`, `--lookup`, `--omit-header`, `--crlf`, `-f` |
| `verify` | Verify an exported file (and its source, if present) against its manifest and report the scope — `output+source` when the source was found and matched, `output-only` otherwise; `--require-source` turns a missing source into a failure; `--source PATH` says where the evidence is now; exit code 1 on mismatch |
| `count` | Count records with a full quote-aware scan, writing nothing |
| `hash` | Compute digests of any file |
| `gen` | Generate a deterministic synthetic dataset (`--profile narrow\|wide\|quotes\|ragged`, `--size` or `--rows`, `--seed`) |

### Export, redaction, enrichment

```
gridsift export proxy.csv -o shareable.csv -s '/c2/beacon' -c path \
    --redact user=hmac --redact src_ip=ip:16 --redact user_agent=drop \
    --redact email=mask --redact sha256=partial:8 --hmac-key-file key.txt \
    --geoip dst_ip=GeoLite2-ASN.mmdb --domain host --lookup src_ip=assets.csv:ip:owner,site
```

| redaction | effect |
|---|---|
| `COL=drop` | the column disappears (header too) |
| `COL=mask[:TEXT]` | every non-empty value becomes `TEXT` (default `[REDACTED]`) |
| `COL=partial[:N]` | first `N` characters kept, the rest `*` |
| `COL=ip[:BITS]` | host bits zeroed: `10.1.243.150` → `10.1.0.0` for 16; non-IPs are masked |
| `COL=hmac[:LEN]` | deterministic pseudonym: `LEN` hex chars of HMAC-SHA256(key, value); key from `--hmac-key-file` or `GRIDSIFT_HMAC_KEY` |

| enrichment | derived columns | data |
|---|---|---|
| `--geoip COL=FILE.mmdb` | `COL.country`, `COL.city` (city DB) or `COL.asn`, `COL.as_org` (ASN DB) | an MMDB file you import (GeoLite2, DB-IP Lite, …) |
| `--domain COL` | `COL.registrable`, `COL.suffix`, `COL.subdomain` | the Public Suffix List snapshot compiled into the binary |
| `--lookup COL=FILE.csv:KEY[:V1,V2]` | one column per value column | any local CSV: asset inventory, IOC list, resolver-cache export |

Untouched columns keep their exact bytes. Enrichment sees the original
value even when the source column is redacted. The manifest records the
redaction policy (with a key fingerprint, never the key), every dataset by
name, size and SHA-256, and for lookups the key and value columns used —
see [manifest.md](manifest.md).

### What gridsift refuses to do

- Write over the evidence, under any name: the output, its manifest, the
  index sidecar and every temporary file are checked against the source
  (by path and by file identity) before anything is created.
- Overwrite an existing output without `-f`.
- Export from a source that changed on disk since it was opened (size or
  modification time differ); reopen it instead. Within one `gridsift`
  command the window is short, but the check runs before the export
  starts and again before it is published.
- Reuse a cached index that was built with different parser settings:
  `--no-header`, `-d` and `--no-quote` get their own sidecar, so the same
  explicit options give the same records with or without a cache.

An export publishes the manifest first and then the output, each by
atomic rename, so the destination never holds an output without its
provenance, and an interrupted overwrite leaves the previous files intact.

### Before sharing a manifest

The manifest is deliberately complete: it holds the search patterns,
absolute paths and dataset names that make the finding reproducible.
Redacting a column does not remove a username that was typed as a search
term, and paths may reveal case names. Keep the full manifest with the
case; review it (or strip `source.path`, `output.path` and the queries)
before it leaves the case boundary.

### Memory

The source is never loaded into memory. Fixed read buffers and the sparse
index are what the index pass and record navigation use (about 35 MiB at
both 1 GiB and 10 GiB on the reference machine). Searches add a compressed
bitmap of matching records; counts keep a capped table per worker and
switch to lossy counting beyond it; lookup tables are loaded whole; the
desktop application keeps a row cache and its UI on top (~200–300 MiB on
a 1 GiB file). Every command prints its own peak RSS; on Windows the
measurement is not available and is shown as `n/a`. The numbers, the
machine and the cache state behind each claim are in
[../bench/README.md](../bench/README.md).

### jq recipes

```
gridsift info   proxy.csv --json | jq '.dialect'
gridsift index  proxy.csv --json | jq '{records, sha256, field_mismatches, index_path}'
gridsift search proxy.csv '/c2/beacon' --json | jq '.matches'
gridsift freq   proxy.csv -c src_ip --json | jq '.top[] | [.value, .count] | @tsv' -r
gridsift freq   proxy.csv -c host.registrable --domain host --json | jq '.top[:10]'
gridsift timeline proxy.csv -c timestamp -b 1h --json | jq '.buckets[] | [.start, .count] | @tsv' -r
gridsift profile proxy.csv --json | jq '.columns[] | {name, detected, confidence}'
gridsift verify beacon.csv --json | jq '.ok'
```

### Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | error (file not found, unreadable, invalid arguments) — or, for `verify`, a digest mismatch |

## Desktop application

```
gridsift-desktop                                  # empty window: drop a file or press ⌘O / Ctrl+O
gridsift-desktop proxy.csv                        # open a file
gridsift-desktop proxy.csv --search '/c2/beacon' --dashboard
```

Launch options (`--search PATTERN [--regex]`, `--count COLUMN`,
`--timeline`, `--dashboard`, `--domain COLUMN`) reproduce a state on
start; they exist for demos and screenshots.

### The window

- **Title bar** — file name, size, and the two badges: *EVIDENCE · READ
  ONLY* and *STRICT OFFLINE*.
- **Evidence sidebar** — facts only: records, SHA-256 (✔ once computed),
  index state and time, dialect, malformed counts. Below it every column
  with its detected type; a click opens the column menu: *Count values ·
  Timeline · Search in this column · Enrich… · Redact on export…*. Then the
  active enrichment rules and **Export finding…**.
- **Command bar** — one search field with *Regex*, *Exact* (whole-field
  match), *Aa* (case-insensitive), *Invert* and a column chip. Under it the
  **selection lineage** as chips, each with its match count:
  `"/c2/beacon" 483,485 ▶ timestamp 09-22 14:00 – 16:00 12,331`. Clicking
  a chip reverts to that step (no rescan), × on the last chip removes it,
  *clear* drops the selection. *show only matches* toggles between the
  filtered view and highlight mode with prev / next. A step whose scan was
  cancelled or failed is shown in khaki with *(cancelled)* / *(failed)*:
  it cannot be exported, counted, charted or searched within — remove it.
- **Source changed** — the file's size and modification time are checked
  every couple of seconds and before every scan and export. If they
  differ from what was opened, a red banner appears in the sidebar, running
  work is cancelled and exports are disabled until the file is reopened.
- **Grid** — virtual rows over the index; typed headers; derived columns in
  green. *Go to row* jumps by ordinal.
- **Analysis dock** — *Dashboard* (below), *Timeline* (drag a range on the
  chart → *Filter to range*), *Values* (top-N with share bars; click a
  value to filter by it), *Profile* (the full column profile).
- **Dashboard** — built from the column profile the first time it is
  opened: the timestamp column becomes a timeline card; columns with a
  handful of values (protocol, action, HTTP status, booleans) become pies;
  hosts, addresses, ports and paths become top-value bars; hashes, free
  text and plain numbers are skipped. Six panels at most by default —
  *+ add column* or a column's *Add to dashboard* adds more, a panel's
  menu switches pie ↔ bars or removes it, *Auto-build* starts over. The
  charts are counted over the current selection and recount when it
  changes; clicking a slice or a bar filters to that exact value (a new
  lineage chip), and dragging on the timeline card selects a range.
- **Status bar** — first rows time, index time, rows cached, peak RSS.

### An investigation, end to end

1. Open `proxy-2026-09.csv` (1 GiB). Rows are on screen in a few
   milliseconds; the sidebar shows the SHA-256 and the record count once
   the background pass finishes (about a second per GiB).
2. Search `/c2/beacon`. 483,485 matches in ~0.3 s; the grid now shows only
   those rows and a chip records the step.
3. From the `timestamp` column, *Timeline*. Drag across the spike, *Filter
   to range* — a second chip, 12,331 records.
4. From `src_ip`, *Count values*: the top talkers within the range. Click
   one — a third chip, an exact-field match, so it selects precisely the
   rows the count showed.
5. *Enrich…* → `host` → Domain; `host.registrable` appears in green.
6. **Export finding…** shows the lineage, lets you redact `user` (HMAC)
   and drop `user_agent`, and writes `beacon-1400-1600.csv` next to its
   manifest.
7. Later, on any machine: `gridsift verify beacon-1400-1600.csv`.

Nothing in these steps modified the source, and the manifest lists every
step with its counts.
