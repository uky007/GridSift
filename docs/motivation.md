# Why gridsift exists

This document is the case for the tool: the situation it was built for,
who it is for, what they do with it, and why the tools that already exist
did not close the gap. The comparison with existing tools is in
[survey.md](survey.md); what the tool does is in
[description.md](description.md).

## The situation

Digital forensics and incident response (DFIR) work runs on exported
tables. When a responder arrives — at a client site, on a jump host, in a
lab with no outbound network — the evidence that actually reaches them is
rarely a live console. It is files:

- a proxy or web-gateway log export for the last 30 days: 10–100 GB of CSV;
- an EDR "all events for these hosts" export: tens of millions of rows,
  wide, with quoted command lines containing commas and newlines;
- firewall, VPN, NetFlow or DNS resolver exports from a network team;
- authentication and audit logs pulled from a cloud tenant as CSV;
- the SIEM's own search results, exported because the analyst's access to
  the SIEM ends when the engagement does;
- CSV timelines produced by forensic tooling (Plaso, KAPE and the EZ
  tools, Velociraptor hunts, Hayabusa / Chainsaw over EVTX).

The questions asked of these files are always the same shape: *does this
indicator appear, where, when, from which hosts, how often; what happened
in the two hours around it; give me those rows so I can put them in the
report.* This is an interactive loop — search, look, pivot, narrow, look
again — not a batch job.

And the files are evidence. What is extracted from them may end up in an
incident report, a regulator's file, an insurance claim or a courtroom.
The analyst must be able to say what the source was, prove it was not
modified, and show how the extract was derived from it — months later,
possibly on another machine, possibly by someone else.

## What goes wrong today

Every widely used answer fails on at least one of the four constraints
that this situation imposes: *size*, *interactivity*, *evidence handling*
and *no network*.

| approach | what breaks |
|---|---|
| Spreadsheets (Excel, LibreOffice Calc) | 1,048,576-row limit; a 30-day proxy log is 50× that. Opening a subset means someone already cut the evidence with another tool |
| Log viewers (klogg, glogg, lnav, …) | handle the size, but are line-oriented: a quoted field with an embedded newline is two "lines"; regex search is possible, pivoting (top values, a time histogram, "only the rows of this host") is not |
| Large-file text editors with a CSV mode (EmEditor) | handle the size and the CSV structure — EmEditor's CSV mode understands newlines inside cells and has filter, sort and pivot tables — but it is a Windows-only, proprietary *editor*: the file is something to change, and nothing records what was derived from it |
| Command-line CSV tools (qsv, xsv, xan, Miller, csvkit) | fast and correct on huge files, and gridsift borrows from them — but the loop of *look → refine → look* becomes a sequence of commands whose intermediate files are copies of evidence with no provenance |
| Loading into a database or a notebook (DuckDB, SQLite, pandas) | powerful, but it converts the evidence into another form; the link between a result and the original bytes is the analyst's memory. Notebooks are also not something most responders keep on an engagement laptop |
| Ingesting into a SIEM or a search stack (Splunk, Elastic, Timesketch) | the right tool if the infrastructure exists; for a one-off export it means a server, an index build measured in hours, a licence or ingest cap, and a copy of the evidence living on that server |
| DFIR timeline viewers (Timeline Explorer) | built for exactly this audience, free and widely recommended; Windows-only, nothing documented about how it scales, and no notion of source hash or of what was exported |
| Commercial large-CSV editors (Modern CSV, …) | cross-platform and fast, but they are *editors*: the source is something to change, not evidence to protect, and "your data stays local" is a policy statement rather than a property of the binary |

Two consequences of these gaps are visible in practice. First, analysts
split the evidence up front (`head`, `grep`, `split`) to make it fit a
tool, and the split files — not the evidence — become what the findings
refer to. Second, the derivation of a finding lives in a chat thread or in
the analyst's shell history; reproducing it later means redoing it.

## Who it is for

- **Incident responders** working from exported logs on a client site or an
  isolated network, who need answers in minutes and a defensible extract
  at the end.
- **SOC analysts and threat hunters** handed a large export by another
  team ("here is everything from that subnet, find the beacon").
- **Forensic examiners** who must maintain chain of custody over derived
  artefacts and be able to verify, later, that an extract came from a
  specific source file.
- **Threat researchers** triaging large third-party datasets — passive DNS
  dumps, certificate logs, leaked-credential lists — where reaching out to
  the network during analysis is itself a risk.
- **Anyone sharing findings across an organisational boundary** who needs
  to redact identities but keep them correlatable (the same user maps to
  the same pseudonym across files).

## How it is used

A typical engagement, end to end:

1. *Open the export.* The proxy log — 40 GB, say; the largest file measured
   so far is 10 GiB, and nothing in the design changes above it — opens in
   milliseconds; rows are on screen while the index and the SHA-256 are
   computed in the background. The window says what it is looking at:
   size, record count, digest, parser settings, malformed-row counts.
2. *Search for the indicator.* `/c2/beacon`, or a regex over the
   user-agent column. Matches are counted and shown; nothing is copied.
3. *Narrow and pivot.* Timeline of the matches; drag the spike; filter to
   that window. Top source addresses inside it; click the outlier. Each
   step is a chip; each chip is a count; any chip can be revisited without
   rescanning.
4. *Enrich, offline.* Registrable domain of the host column from the
   bundled Public Suffix List; ASN from a GeoLite2 file the analyst
   brought on a USB stick; owner and site of the source address from the
   client's asset CSV. Each dataset is identified by hash.
5. *Export the finding.* The rows of the last step, as their exact source
   bytes or with the user column pseudonymised and the user-agent dropped,
   plus a manifest: source identity, parser settings, every step with its
   count, the datasets used, the redaction policy, the output's digest.
6. *Verify, later.* `gridsift verify finding.csv` re-hashes the output and,
   if present, the source, and prints what the finding claims to be.

Other recurring uses:

- **Triage before ingestion**: decide in ten minutes whether a 60 GB export
  is worth loading into the SIEM at all, and which two days of it.
- **Shareable extracts**: a partner or vendor gets the beacon rows with
  HMAC-pseudonymised usernames and /16-truncated internal addresses; the
  manifest records the policy, never the key.
- **Reproducing a colleague's finding**: the manifest holds the queries
  verbatim; the same steps over the same source give the same counts.
- **Working where nothing may leave the machine**: the tool has no
  network code path at all, so "strictly offline" is a property of the
  binary, not a setting.

## What follows from this — the design principles

1. **The source is evidence.** Opened read-only; never rewritten; hashed on
   open. Every path the tool writes — output, manifest, index sidecar,
   their temporaries — is checked against the source before anything is
   created, and a source that changes on disk is detected before a scan or
   an export goes ahead. Everything the analyst produces is a *new* file
   that names its source.
2. **Memory does not grow with the file.** The source is never loaded; a
   sparse, quote-aware index of a few KiB per GiB and fixed buffers are
   what navigation needs, so the index pass measures the same ~35 MiB at
   1 GiB and at 10 GiB. Results (match sets, count tables, lookup tables)
   take memory in proportion to themselves, never to the file, and the
   design does not change at 100 GiB.
3. **The investigation is visible and recorded.** The chain of selection
   steps is on screen and in the manifest; it is the same object. A step
   that was cancelled or failed is marked as such and cannot be exported,
   counted or filtered further — a partial scan never passes for a result.
4. **Offline is a guarantee, not an option.** No telemetry, no update
   checks, no DNS. Enrichment reads local datasets identified by hash.
5. **Numbers are honest.** Exact counts are exact; lossy counts, estimated
   cardinalities and sampled profiles say so and state their bounds. Every
   command reports elapsed time, throughput and peak memory.
6. **Correctness over convenience.** Records are found by a parser-state
   index, not by newlines; malformed rows are counted, not silently
   repaired; the scanner is checked against an independent parser.

## What it is not

- Not a spreadsheet or an editor: there are no formulas and no in-place
  edits. Analyst annotations are planned as a sidecar overlay that becomes
  a new file only on export.
- Not a SIEM: no ingestion, no correlation rules, no dashboards over many
  sources. It is the tool you use on the file *before* — or instead of —
  the SIEM.
- Not a forensic suite: it does not parse disk images or artefacts; it
  works on the delimited outputs that such suites and platforms produce.
- Not a database: whole-file sorts and joins are out of scope for now (an
  embedded out-of-core engine over a selection is on the roadmap).

## Why a new tool rather than a plugin

The pieces exist separately — bounded-memory viewers, fast CSV CLIs,
embedded analytical engines, offline GeoIP readers — and gridsift reuses
several of them as libraries. What did not exist was the *combination*
under evidence-handling rules: a viewer whose index is quote-aware, whose
selection lineage is a provenance record, whose enrichment is offline by
construction, and whose export is verifiable. Bolting a manifest onto an
editor does not give that; the read-only, hash-on-open, record-everything
posture has to be the core, not a feature.

Rust was chosen so that the core, the command-line tool and the desktop
application are one statically linked codebase with no runtime to install
on the engagement laptop, and so that the parser and index can be verified
by property tests against an independent implementation.

## Status and evidence for the claims

The engine, the command-line tool and the desktop application are
implemented; measurements on 1–10 GiB synthetic data are in
[../bench/README.md](../bench/README.md) (first rows in milliseconds; index
+ SHA-256 at ~1.3 GiB/s; search at 2–13 GiB/s on ten cores; peak RSS
identical at 1 and 10 GiB). The synthetic datasets are generated
deterministically by the tool itself, so every number can be reproduced
from `(profile, seed, size)` and checked by hash. The 100 GB cold-cache
run, real GeoIP databases and Windows / Linux numbers are the next
validation steps ([roadmap.md](roadmap.md)).
