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
      "matches": 12331
    },
    {
      "op": "enrich",
      "rules": [
        { "column": 5, "name": "host", "provider": "domain",
          "derived": ["host.registrable", "host.suffix", "host.subdomain"],
          "dataset": { "name": "public-suffix-list", "version": "2.1.238" } }
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
  "selection": { "kind": "matches", "records": 12331 },
  "output": {
    "path": "/cases/2026-0917/findings/beacon-1400-1600.csv",
    "name": "beacon-1400-1600.csv",
    "format": "csv",
    "content": "records-redacted-enriched",
    "header": true,
    "terminator": "\n",
    "records": 12331,
    "size": 2210488,
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
| `search` | `query` (`pattern`, `kind` = `literal`/`regex`, `case_insensitive`, `columns` or `null` for all, `invert`), `matches` | the records matching the query, within the previous step |
| `time_range` | `column`, `name`, `from`, `to` (ISO 8601 UTC, `to` exclusive), `matches` | the records whose timestamp column is in range, within the previous step |
| `enrich` | `rules[]`: `column`, `name`, `provider` (`geoip`, `domain`, `lookup`), `derived` names, `dataset` (`name`, `size`, `sha256`, and for MMDB `database_type` and `build_epoch`; for the PSL its `version`) | derived columns appended to the output, identified by the exact dataset that produced them |
| `redact` | `policy.rules[]`: `column`, `name`, `method` and its parameters | how columns were rewritten; for `hmac` only a fingerprint of the key (SHA-256 of the key, truncated) is recorded, never the key |

Selection steps (`search`, `time_range`) are nested: each applies within
the matches of the previous one, and `matches` is the count after that
step. In the desktop application the same chain is what the lineage chips
show.

### `output`

| field | meaning |
|---|---|
| `path`, `name` | where the file was written |
| `format` | `csv` |
| `content` | `raw-records` (each record's bytes exactly as in the source, followed by `terminator`), `records-redacted`, `records-enriched` or `records-redacted-enriched` |
| `header` | whether the header record was written |
| `terminator` | `"\n"` or `"\r\n"` |
| `records`, `size` | what was written |
| `sha256`, `blake3` | digests of the output file |

## Verification

```
gridsift verify findings/beacon-1400-1600.csv
gridsift verify findings/beacon-1400-1600.csv --source /mnt/evidence/proxy-2026-09.csv
gridsift verify findings/beacon-1400-1600.csv --skip-source
```

`verify` re-hashes the output and, unless `--skip-source` is given, the
source (at the manifest's path or at `--source`), compares both against the
manifest, and prints the operations so the reader can see what the output
claims to be. Any mismatch exits with code 1.

## What the manifest does not claim

- It does not prove *who* ran the export or *when* beyond the writer's
  clock; it is not signed. Signing is a candidate for a later version.
- It records the transformation, not the analyst's reasoning.
- `raw-records` outputs preserve each record's bytes, but record terminators
  are normalised to `terminator`; a byte-for-byte copy of the source is
  only obtained when the source used the same terminator throughout.
