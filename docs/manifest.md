# The provenance manifest

Every file gridsift exports is accompanied by `<output>.manifest.json`. The
manifest ties the output to the evidence it was derived from: the source
identity, the parser settings, every operation that shaped the selection
(queries verbatim, so they can be replayed), and the output's own digest.
`gridsift verify` recomputes both digests later.

It is a deliberately small, W3C-PROV-inspired record — *entity (source) →
activities (operations) → entity (output)* — not a full PROV document.

## Example

```json
{
  "gridsift_manifest": 1,
  "created_at": "2026-09-28T00:53:41Z",
  "tool": { "name": "gridsift", "version": "0.1.0", "platform": "macos-aarch64" },
  "source": {
    "path": "/cases/2026-0917/proxy-2026-09.csv",
    "name": "proxy-2026-09.csv",
    "size": 1073741833,
    "sha256": "b7f27b25712b96b42e5a27de2d52fd9078e1b733816b774025a2dc6fefb1dcc0",
    "blake3": null,
    "mtime": "2026-09-27T11:35:04Z",
    "dialect": { "delimiter": ",", "quote": "\"", "header": true },
    "records": 4840035
  },
  "operations": [
    {
      "op": "search",
      "query": { "pattern": "/c2/beacon", "kind": "literal",
                 "case_insensitive": false, "columns": [6], "invert": false },
      "matches": 483485
    },
    {
      "op": "time_range",
      "column": 0, "name": "timestamp",
      "from": "2026-09-22T14:00:00Z", "to": "2026-09-22T16:00:00Z",
      "matches": 12331, "reference_year": 2026
    },
    {
      "op": "search",
      "query": { "pattern": "10.5.65.5", "kind": "exact",
                 "case_insensitive": false, "columns": [1], "invert": false },
      "matches": 4120
    },
    {
      "op": "enrich",
      "rules": [
        { "column": 5, "name": "host", "provider": "domain",
          "derived": ["host.registrable", "host.suffix", "host.subdomain"],
          "dataset": { "name": "public-suffix-list", "kind": "psl", "version": "psl 2.1.238" } },
        { "column": 1, "name": "src_ip", "provider": "lookup",
          "derived": ["src_ip.owner", "src_ip.site"],
          "dataset": { "name": "assets.csv", "kind": "csv", "size": 18234,
                       "sha256": "9c1e…", "records": 412,
                       "lookup": { "key": "ip", "values": ["owner", "site"],
                                   "delimiter": ",", "quote": "\"", "header": true } } }
      ]
    },
    {
      "op": "redact",
      "policy": { "rules": [
        { "column": 9, "name": "user", "method": "hmac", "length": 16,
          "key_fingerprint": "e1f678959c40ab55" },
        { "column": 1, "name": "src_ip", "method": "ip_prefix", "bits": 16 },
        { "column": 11, "name": "user_agent", "method": "drop" }
      ] }
    }
  ],
  "selection": { "kind": "matches", "records": 4120 },
  "output": {
    "path": "/cases/2026-0917/findings/beacon-1400-1600.csv",
    "name": "beacon-1400-1600.csv",
    "format": "csv",
    "content": "records-redacted-enriched",
    "header": true,
    "terminator": "\n",
    "records": 4120,
    "size": 741020,
    "sha256": "5decb233886da7e09eb57a286b079efc879b2e945e99c76b2074b3b24829380d",
    "blake3": null
  }
}
```

## Fields

### Top level

| field | meaning |
|---|---|
| `gridsift_manifest` | format version, currently `1` |
| `created_at` | when the export finished, ISO 8601 UTC |
| `tool` | `name`, `version` (crate version) and `platform` (`os-arch`) of the writer |
| `source` | the evidence the output was derived from (below) |
| `operations` | the steps that shaped the selection and the output, in application order (below) |
| `selection` | what subset of the source was written: `{"kind":"all"}`, `{"kind":"matches","records":N}` or `{"kind":"range","first":F,"count":N}` |
| `output` | the file that was written (below) |

### `source`

| field | meaning |
|---|---|
| `path`, `name` | canonical path and file name at export time |
| `size` | bytes |
| `sha256`, `blake3` | lowercase hex digests of the whole file, `null` if not computed |
| `mtime` | modification time, ISO 8601 UTC |
| `dialect` | the parser settings used: `delimiter`, `quote` (`null` = quotes are literal), `header` |
| `records` | data records (header excluded) when the index was complete |

### `operations`

Each entry has an `op` tag:

| `op` | fields | meaning |
|---|---|---|
| `search` | `query` (`pattern`, `kind` = `literal` / `regex` / `exact`, `case_insensitive`, `columns` or `null` for all, `invert`), `matches` | the records matching the query, within the previous step. `exact` means a whole field equals the pattern — the kind a value-count pivot records |
| `time_range` | `column`, `name`, `from`, `to` (ISO 8601 UTC, `to` exclusive), `matches`, `reference_year` (the year assumed for timestamp formats that carry none, such as syslog) | the records whose timestamp column is in range, within the previous step |
| `enrich` | `rules[]`: `column`, `name`, `provider` (`geoip`, `domain`, `lookup`), `derived` names, `dataset` (`name`, `kind`, `size`, `sha256`, `records`; for MMDB `database_type` and `built`; for the PSL its `version`; for a lookup table `lookup` = `key`, `values`, and the `delimiter` / `quote` / `header` it was parsed with) | derived columns appended to the output, identified by the exact dataset and join settings that produced them |
| `redact` | `policy.rules[]`: `column`, `name`, `method` and its parameters | how columns were rewritten; for `hmac` only a fingerprint of the key (SHA-256 of the key, truncated) is recorded, never the key |
| `edit` | `edits`: `version` (the name of the saved version the edits came from), `cells[]`: `record`, `column`, `name`, `was_sha256` (SHA-256 of the original value's bytes), `value` (the value written; **absent** for a column the same export redacts), `marks` (marked rows in the version; marks are not part of the output) | the analyst's cell edits applied to the written records — only those: an edit of a record outside the selection was not applied and is not listed. The original values are recorded by hash so the manifest can prove what changed without disclosing it; note that a hash of a short, guessable value does not hide it |

Selection steps (`search`, `time_range`) are nested: each applies within
the matches of the previous one, and `matches` is the count after that
step. In the desktop application the same chain is what the lineage chips
show. Only steps whose scan completed can reach a manifest: a cancelled or
failed scan is refused for export, so a recorded count is always the count
of a full pass.

### `output`

| field | meaning |
|---|---|
| `path`, `name` | where the file was written |
| `format` | `csv` |
| `content` | `raw-records` (each record's bytes exactly as in the source, followed by `terminator`), or `records` with what changed them, in this order: `-edited` (cell edits were applied to at least one written record), `-redacted`, `-enriched` — e.g. `records-edited`, `records-redacted-enriched`, `records-edited-redacted-enriched` |
| `header` | whether the header record was written |
| `terminator` | `"\n"` or `"\r\n"` |
| `records`, `size` | what was written |
| `sha256`, `blake3` | digests of the output file |

## How an export is published

1. The output plan is checked against the evidence: the output path, the
   manifest path and both temporary files must not be the source (by path,
   and by file identity if they exist).
2. The source must still have the size and modification time it was
   opened with; otherwise the export is refused.
3. Records are written to a temporary file next to the output and hashed
   as they are written.
4. The source identity is checked again; then the manifest is written to
   its own temporary file and renamed into place; then the output is
   renamed into place. Both renames replace atomically.

An interrupted overwrite therefore leaves the previous output and manifest
intact as long as the interruption happens before the first rename; the
one window that remains — a crash between the two renames — leaves a new
manifest next to the older output, which `verify` reports as a mismatch.
There is never an output without a manifest.

## Verification

```
gridsift verify findings/beacon-1400-1600.csv
gridsift verify findings/beacon-1400-1600.csv --source /mnt/evidence/proxy-2026-09.csv
gridsift verify findings/beacon-1400-1600.csv --require-source
gridsift verify findings/beacon-1400-1600.csv --skip-source
```

`verify` re-hashes the output and, unless `--skip-source` is given, the
source (at the manifest's path or at `--source`), compares their sizes and
digests with the ones recorded in the manifest, and prints the operations
so the reader can see what the output claims to be. It states its
**scope**: `output+source` when the source was found and matched, or
`output-only` when the source was skipped or not found. Any mismatch exits
with code 1; with `--require-source`, so does a missing source. In `--json`
output the same appears as `scope` and `source_checked`.

What a successful `output+source` check establishes is exactly this: the
two files on disk are the ones the manifest describes. It does not re-run
the recorded operations to show that this output follows from that source
(the queries are recorded so that a reader can), and it does not establish
that the manifest itself is authentic — manifests are unsigned.

## What the manifest does not claim

- It does not prove *who* ran the export or *when* beyond the writer's
  clock; it is not signed. Signing is a candidate for a later version.
- It records the transformation, not the analyst's reasoning.
- It does not re-run anything: `verify` checks digests, it does not replay
  the operations (the queries are stored verbatim so that a reader can).
- The source-change check that guards an export is a metadata check (size
  and modification time), which catches a rewritten file but is not a
  cryptographic guarantee; the source digest in the manifest is.
- `raw-records` outputs preserve each record's bytes, but record terminators
  are normalised to `terminator`; a byte-for-byte copy of the source is
  only obtained when the source used the same terminator throughout.

## What the manifest reveals

Everything needed to reproduce the finding: search patterns as typed,
absolute paths of the source, the output and every dataset, dataset names
and digests. Redacting a column of the output does not redact the manifest.
Keep the full manifest with the case; before a manifest leaves the case
boundary, review it — a share-safe variant (relative paths, hashed query
terms) is on the roadmap.
