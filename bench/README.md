# Benchmarks

Reproducible measurements of the core engine. Datasets are generated with
`gridsift gen`, so anyone can regenerate the exact bytes from `(profile, seed,
size)` and confirm them by hash. Data files live outside the repo
(`bench/data/` is git-ignored).

## Procedure

```
B=./target/release/gridsift
D=bench/data; mkdir -p $D

$B gen  --profile narrow --size 10G -o $D/narrow-10g.csv        # deterministic, seed=1
$B info  $D/narrow-10g.csv -n 3                                   # time to first rows, no scan
$B index $D/narrow-10g.csv --index $D/narrow-10g.gsix            # sparse index + SHA-256 in one pass
$B rows  $D/narrow-10g.csv --index $D/narrow-10g.gsix --start 40000000 --count 2   # random jump
$B count $D/narrow-10g.csv                                        # scan-only throughput
```

Every command prints elapsed time, throughput and peak RSS (`--json` for
machine-readable output). Always state whether the OS page cache was cold or
warm; on macOS a cold run needs `sudo purge` first.

Correctness cross-check: `gridsift count` on the `quotes` profile (embedded
newlines, quotes, commas) must match an independent parser, e.g.

```
python3 -c "import csv,sys; csv.field_size_limit(1<<30); print(sum(1 for _ in csv.reader(open(sys.argv[1], newline='')))-1)" $D/quotes-100m.csv
```

## Baseline — 2026-09-27

Machine: Apple M1 Max (10 cores), 32 GB RAM, internal NVMe, macOS 26.6.2,
Rust 1.93 release build (`lto = "fat"`). **Warm page cache** (files were just
written and fit in RAM). Profile `narrow` (13 columns, ~222 B/row, quoted
user-agent field), seed 1.

| Size | Records | `info` first rows | `index` (+SHA-256) | index size | `rows` far jump | `count` scan | peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 GiB | 4,840,035 | 6.0 ms | 1.16 s (885 MiB/s) | 18.7 KiB (0.002 %) | 0.16 ms | 0.46 s (2,245 MiB/s) | 10.4 MiB |
| 10 GiB | 48,399,758 | 2.0 ms | 13.0 s (787 MiB/s) | 184.9 KiB (0.002 %) | 29 ms | 5.34 s (1,918 MiB/s) | 10.4 MiB |

Correctness: `quotes` profile, 100 MiB, 697,381 records — identical count from
Python's `csv` module; 0 field-count mismatches.

Observations:

- Peak RSS is identical at 1 GiB and 10 GiB: memory is bounded by the read
  buffers plus the checkpoint table, not by file size.
- The index pass is hash-bound: scanning alone runs at ~2 GiB/s, SHA-256 in
  the same thread brought the pass down to ~0.8 GiB/s.
- Generation runs at ~430 MiB/s, so a 100 GiB dataset takes ~4 minutes to
  create.

Same day, after moving the digest onto its own thread (chunks shared through
a small buffer pool; 1 GiB, warm cache):

| `index` variant | time | throughput | peak RSS |
|---|---:|---:|---:|
| SHA-256 (default) | 0.77 s | 1,336 MiB/s | 34.5 MiB |
| no digest | 0.37 s | 2,793 MiB/s | 10.6 MiB |
| SHA-256 + BLAKE3 | 1.22 s | 837 MiB/s | 34.6 MiB |

SHA-256 (single-threaded by nature, ~1.4 GiB/s with ARMv8 crypto extensions)
is now the ceiling of the default pass; the scan itself is no longer on the
critical path.

Desktop app (`gridsift-desktop`, same 1 GiB file, no cached sidecar): first
rows on screen in **3.6 ms**, background index + SHA-256 finished in
**1.05 s** while the grid stayed interactive. Before the index/hash threads
were given `QOS_CLASS_USER_INITIATED`, macOS scheduled them on efficiency
cores and the same build took 2.62 s — worth remembering for any background
work in the GUI.

### Search (same 1 GiB file, index present, warm cache)

`gridsift search` cuts the file at index checkpoints into ~64 MiB ranges and
scans them on all cores; matches accumulate in a roaring bitmap.

| Query | Matches | Threads | Time | Throughput |
|---|---:|---:|---:|---:|
| literal `/c2/beacon` | 483,485 | 1 | 0.52 s | 1,980 MiB/s |
| literal `/c2/beacon` (desktop, filtered view) | 483,485 | 10 | 0.34 s | 2.96 GiB/s |
| literal `deny,"curl` (desktop) | 18,324 | 10 | 0.12 s | 8.6 GiB/s |
| literal `KAACFI`, column `host`, case-insensitive | 1 | 10 | 0.10 s | 9.6 GiB/s |
| regex `deny,"curl/[0-9.]+"` | 1 | 10 | 0.08 s | 12.8 GiB/s |
| literal `allow`, inverted | 144,743 | 10 | 0.08 s | 12.3 GiB/s |

The literal count was cross-checked against a Python `in`-per-line scan
(483,485). Many-match queries are bounded by bitmap merging and by the
per-hit bookkeeping, few-match queries by memory bandwidth.

A first version read slices through the mapping; with 10 threads faulting
pages of a partially evicted file it ran at 285 MiB/s. Slices are now read
with positioned reads into per-thread buffers (only records straddling a
slice boundary go through the mapping), which is what a 100 GiB file — never
cache-resident — needs, and it keeps RSS at a few MiB per thread.

### Export (same machine, warm cache)

| Export | Records | Output | Time |
|---|---:|---:|---:|
| matches of `/c2/beacon` in `path` (1 GiB source, via index jumps) | 483,485 | 101.6 MiB | 0.58 s |
| all records of the `quotes` torture file (100 MiB, sequential) | 697,381 | 99.7 MiB | 0.22 s |

`gridsift verify` on the first export re-hashed the 1 GiB source and the
output; a single appended byte on an output is reported as a mismatch (exit
code 1).

With five redaction rules (hmac, ip prefix, drop, partial, mask) the same
483,485-record export took 1.45 s: rewritten fields cost about 2.5× the
raw copy.

### Profile

`gridsift profile` on the 1 GiB `narrow` file: 2,048 rows sampled from the
head and 48 positions across the file, all 13 columns typed with 100 %
share (timestamp, ipv4 ×2, port, categorical, domain, categorical,
http_status, integer, text, categorical ×2, sha256) in 0.6 s, dominated by
page faults at the 48 sample positions.

### Value counts (`freq`, 1 GiB, warm cache, 10 threads)

| Column | Distinct | Mode | Time | Throughput | peak RSS |
|---|---:|---|---:|---:|---:|
| `status` (5 values) | 5 | exact | 0.37 s | 2.7 GiB/s | 47 MiB |
| `host` | 5,829 | exact | 0.12 s | 8.2 GiB/s | 53 MiB |
| `sha256` (unique per row) | 4,858,496 est. (true 4,840,035) | lossy, bound 479 | 0.44 s | 2.3 GiB/s | 323 MiB |
| `dst_port` over the 144,743 records matching `,deny,` | 13,064 | exact | 0.09 s | 11.9 GiB/s | 60 MiB |

The `status` counts were cross-checked against a Python `Counter` over the
same file (identical). The high-cardinality case shows the bounded-memory
fallback: ten workers each keep at most 131,072 exact entries before going
lossy, so RSS stays in the low hundreds of MiB however many distinct values
the column has.

## Still to do

- Cold-cache runs (`sudo purge`), and a 100 GiB run on external storage.
- A 16 GB RAM machine (the survey's "constrained analyst laptop" tier).
- `wide`, `quotes`, `ragged` profiles at 10 GiB.
- Competitor set on the same files and hardware: qsv, xan, DuckDB (CLI
  baselines); EmEditor (Windows), Modern CSV, CEESVEE, Columnar (GUI).
- Windows and Linux numbers from CI-built binaries.
