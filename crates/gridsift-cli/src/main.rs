//! `gridsift` command-line interface.
//!
//! Every command treats the input as read-only evidence. Sidecar files
//! (indexes) are written to the user's cache directory, never next to the
//! source, unless a path is given explicitly.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use gridsift_core::dialect::sniff;
use gridsift_core::enrich::{EnrichRule, Enrichment, GeoIpDb, GeoProvider, LookupTable, Provider};
use gridsift_core::export::{ExportOptions, Selection, Terminator, export};
use gridsift_core::frequency::{FrequencyOptions, FrequencyShared, frequency};
use gridsift_core::hash::{MultiHasher, hash_source, hex};
use gridsift_core::index::{BuildOptions, IndexParams, SparseIndex, bootstrap, build_index};
use gridsift_core::manifest::{Manifest, Operation, OutputInfo, SelectionInfo, SourceInfo};
use gridsift_core::reader::{header_fields, locate_many, locate_records};
use gridsift_core::redact::{
    DEFAULT_HMAC_LENGTH, DEFAULT_MASK, RedactMethod, RedactRule, Redactor,
};
use gridsift_core::search::MatchSet;
use gridsift_core::search::{PatternKind, SearchOptions, SearchQuery, SearchShared, search};
use gridsift_core::semantic::{ProfileOptions, profile as profile_columns};
use gridsift_core::sidecar::default_index_path;
use gridsift_core::synth::{Generator, Profile, Target};
use gridsift_core::sys::{group_thousands, human_bytes, iso8601_utc, peak_rss_bytes};
use gridsift_core::timeline::{TimelineOptions, current_year, timeline};
use gridsift_core::{Dialect, HashSelection, Sniff, Source};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "gridsift",
    version,
    about = "Offline, evidence-safe workbench for very large CSV security data",
    long_about = None
)]
struct Cli {
    /// Machine-readable JSON output on stdout
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sniff the dialect and show the first records without scanning the file
    Info {
        file: PathBuf,
        /// Number of records to show
        #[arg(long, short = 'n', default_value_t = 10)]
        rows: usize,
        #[command(flatten)]
        dialect: DialectArgs,
    },
    /// Build the sparse record index and source digest in one pass
    Index {
        file: PathBuf,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Maximum records between checkpoints
        #[arg(long, default_value_t = 4096)]
        stride_records: u32,
        /// Maximum bytes between checkpoints (accepts K/M/G suffixes)
        #[arg(long, default_value = "4M", value_parser = parse_size)]
        stride_bytes: u64,
        /// Read buffer size (accepts K/M/G suffixes)
        #[arg(long, default_value = "8M", value_parser = parse_size)]
        chunk_size: u64,
        /// Digests to compute in the same pass
        #[arg(long, value_enum, default_value_t = HashAlgo::Sha256)]
        hash: HashAlgo,
        /// Where to write the index (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
        /// Skip per-record field counting (slightly faster, no mismatch stats)
        #[arg(long)]
        no_fields: bool,
    },
    /// Print records by ordinal using the index (falls back to scanning)
    Rows {
        file: PathBuf,
        #[command(flatten)]
        dialect: DialectArgs,
        /// First record ordinal (0-based, header excluded)
        #[arg(long, short = 's', default_value_t = 0)]
        start: u64,
        /// Number of records
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
        /// Print raw record bytes instead of split fields
        #[arg(long)]
        raw: bool,
    },
    /// Search every record for a literal or regex; prints matches and the total
    Search {
        file: PathBuf,
        /// Literal text, or a regular expression with --regex
        pattern: String,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Interpret the pattern as a regular expression
        #[arg(long, short = 'r')]
        regex: bool,
        /// Case-insensitive matching
        #[arg(long, short = 'i')]
        ignore_case: bool,
        /// Restrict matching to a column (header name or 0-based index); repeatable
        #[arg(long, short = 'c')]
        column: Vec<String>,
        /// Select the records that do NOT match
        #[arg(long, short = 'v')]
        invert: bool,
        /// Number of matching records to print
        #[arg(long, short = 'n', default_value_t = 20)]
        show: usize,
        /// Worker threads (0 = all cores)
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Export all records, a range, or the matches of a search to a new file
    /// (exact source bytes per record) with a provenance manifest
    Export {
        file: PathBuf,
        /// Output file; `<output>.manifest.json` is written next to it
        #[arg(long, short = 'o')]
        output: PathBuf,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Export only records matching this pattern
        #[arg(long, short = 's')]
        search: Option<String>,
        /// Interpret the pattern as a regular expression
        #[arg(long, short = 'r', requires = "search")]
        regex: bool,
        /// Case-insensitive matching
        #[arg(long, short = 'i', requires = "search")]
        ignore_case: bool,
        /// Restrict matching to a column (header name or 0-based index); repeatable
        #[arg(long, short = 'c', requires = "search")]
        column: Vec<String>,
        /// Select the records that do NOT match
        #[arg(long, short = 'v', requires = "search")]
        invert: bool,
        /// Export a record range `START:COUNT` (0-based, header excluded)
        #[arg(long, conflicts_with = "search", value_parser = parse_range)]
        range: Option<(u64, u64)>,
        /// Do not write the header record
        #[arg(long)]
        omit_header: bool,
        /// Terminate records with CRLF instead of LF
        #[arg(long)]
        crlf: bool,
        /// Overwrite an existing output file
        #[arg(long, short = 'f')]
        force: bool,
        /// Worker threads for the search (0 = all cores)
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
        /// Redact a column: `COLUMN=drop`, `COLUMN=mask[:TEXT]`,
        /// `COLUMN=partial[:KEEP]`, `COLUMN=ip[:BITS]`, `COLUMN=hmac[:LENGTH]`;
        /// repeatable
        #[arg(long)]
        redact: Vec<String>,
        /// File holding the HMAC key for `hmac` redactions (or set GRIDSIFT_HMAC_KEY)
        #[arg(long)]
        hmac_key_file: Option<PathBuf>,
        #[command(flatten)]
        enrich: EnrichArgs,
    },
    /// Verify an exported file (and its source, if present) against its manifest
    Verify {
        /// The exported file
        output: PathBuf,
        /// Manifest path (default: `<output>.manifest.json`)
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Where the source evidence is now (default: the path in the manifest)
        #[arg(long)]
        source: Option<PathBuf>,
        /// Only check the output, not the source
        #[arg(long)]
        skip_source: bool,
    },
    /// Count the values of one column (top-N), over all records or a search's matches
    Freq {
        file: PathBuf,
        /// Column to count (header name or 0-based index)
        #[arg(long, short = 'c')]
        column: String,
        /// Number of values to show
        #[arg(long, short = 'n', default_value_t = 20)]
        top: usize,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Count only records matching this pattern (whole record)
        #[arg(long, short = 's')]
        search: Option<String>,
        /// Interpret the pattern as a regular expression
        #[arg(long, short = 'r', requires = "search")]
        regex: bool,
        /// Case-insensitive matching
        #[arg(long, short = 'i', requires = "search")]
        ignore_case: bool,
        /// Count the records that do NOT match
        #[arg(long, short = 'v', requires = "search")]
        invert: bool,
        /// Worker threads (0 = all cores)
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
        #[command(flatten)]
        enrich: EnrichArgs,
    },
    /// Count records per time bucket of a timestamp column
    Timeline {
        file: PathBuf,
        /// Timestamp column (header name or 0-based index)
        #[arg(long, short = 'c')]
        column: String,
        /// Bucket width: `auto` (default), or e.g. `30s`, `5m`, `1h`, `1d`
        #[arg(long, short = 'b', default_value = "auto")]
        bucket: String,
        /// Maximum buckets for `auto`
        #[arg(long, default_value_t = 60)]
        max_buckets: usize,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Count only records matching this pattern (whole record)
        #[arg(long, short = 's')]
        search: Option<String>,
        /// Interpret the pattern as a regular expression
        #[arg(long, short = 'r', requires = "search")]
        regex: bool,
        /// Case-insensitive matching
        #[arg(long, short = 'i', requires = "search")]
        ignore_case: bool,
        /// Count the records that do NOT match
        #[arg(long, short = 'v', requires = "search")]
        invert: bool,
        /// Year assumed for timestamps without one (syslog); default: this year
        #[arg(long)]
        year: Option<i64>,
        /// Worker threads (0 = all cores)
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Detect what each column holds (ip, domain, hash, timestamp, …) from a sample
    Profile {
        file: PathBuf,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Index to use (default: the user cache directory)
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Count records with a full quote-aware scan (no index written)
    Count {
        file: PathBuf,
        #[command(flatten)]
        dialect: DialectArgs,
        /// Read buffer size (accepts K/M/G suffixes)
        #[arg(long, default_value = "8M", value_parser = parse_size)]
        chunk_size: u64,
    },
    /// Compute digests of a file
    Hash {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = HashAlgo::All)]
        algo: HashAlgo,
        /// Read buffer size (accepts K/M/G suffixes)
        #[arg(long, default_value = "8M", value_parser = parse_size)]
        chunk_size: u64,
    },
    /// Generate a deterministic synthetic dataset
    Gen {
        /// Output file (overwritten if it exists)
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// Row shape
        #[arg(long, short = 'p', default_value = "narrow")]
        profile: Profile,
        /// Number of rows (mutually exclusive with --size)
        #[arg(long, conflicts_with = "size")]
        rows: Option<u64>,
        /// Approximate size in bytes (accepts K/M/G/T suffixes)
        #[arg(long, value_parser = parse_size)]
        size: Option<u64>,
        /// RNG seed
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
}

#[derive(Args, Clone, Debug)]
struct DialectArgs {
    /// Field delimiter: a single character, or `tab`
    #[arg(long, short = 'd')]
    delimiter: Option<String>,
    /// Disable quote handling (quotes become literal bytes)
    #[arg(long)]
    no_quote: bool,
    /// Treat the first record as data rather than a header
    #[arg(long, conflicts_with = "header")]
    no_header: bool,
    /// Force the first record to be treated as a header
    #[arg(long)]
    header: bool,
}

/// Offline enrichment sources, shared by the commands that can derive columns.
#[derive(Args, Clone, Debug, Default)]
struct EnrichArgs {
    /// Add GeoIP/ASN columns from a local `.mmdb`: `COLUMN=PATH` (repeatable)
    #[arg(long = "geoip", value_name = "COLUMN=PATH")]
    geoip: Vec<String>,
    /// Add registrable-domain / suffix / subdomain columns for a column (repeatable)
    #[arg(long = "domain", value_name = "COLUMN")]
    domain: Vec<String>,
    /// Join a local CSV: `COLUMN=PATH:KEY[:VALUE,VALUE…]` (repeatable)
    #[arg(long = "lookup", value_name = "COLUMN=PATH:KEY[:VALUES]")]
    lookup: Vec<String>,
}

impl EnrichArgs {
    fn is_empty(&self) -> bool {
        self.geoip.is_empty() && self.domain.is_empty() && self.lookup.is_empty()
    }
}

/// Build the enrichment described by `--geoip/--domain/--lookup`.
fn build_enrichment(
    args: &EnrichArgs,
    dialect: Dialect,
    header: Option<&[Cow<'_, [u8]>]>,
) -> Result<Option<Enrichment>> {
    if args.is_empty() {
        return Ok(None);
    }
    let column_of = |spec: &str| -> Result<(usize, String)> {
        let c = resolve_columns(&[spec.to_string()], header)?
            .and_then(|c| c.first().copied())
            .expect("one column");
        let name = header
            .and_then(|h| h.get(c))
            .map(|f| field_str(f).into_owned())
            .unwrap_or_else(|| format!("col{c}"));
        Ok((c, name))
    };
    let mut rules = Vec::new();
    let mut dbs: HashMap<PathBuf, Arc<dyn GeoProvider>> = HashMap::new();
    for spec in &args.geoip {
        let (col, path) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--geoip expects COLUMN=PATH, got {spec:?}"))?;
        let (column, name) = column_of(col)?;
        let path = PathBuf::from(path);
        let db = match dbs.get(&path) {
            Some(db) => db.clone(),
            None => {
                let db: Arc<dyn GeoProvider> = Arc::new(
                    GeoIpDb::open(&path).with_context(|| format!("loading {}", path.display()))?,
                );
                dbs.insert(path.clone(), db.clone());
                db
            }
        };
        rules.push(EnrichRule {
            column,
            name,
            provider: Provider::GeoIp(db),
        });
    }
    for spec in &args.domain {
        let (column, name) = column_of(spec)?;
        rules.push(EnrichRule {
            column,
            name,
            provider: Provider::Domain,
        });
    }
    for spec in &args.lookup {
        let (col, rest) = spec.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--lookup expects COLUMN=PATH:KEY[:VALUES], got {spec:?}")
        })?;
        let (column, name) = column_of(col)?;
        let mut parts = rest.splitn(3, ':');
        let path = parts.next().unwrap_or_default();
        let key = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("--lookup needs a KEY column: {spec:?}"))?;
        let values: Vec<String> = parts
            .next()
            .map(|v| v.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let table = LookupTable::load(Path::new(path), key, &values)
            .with_context(|| format!("loading {path}"))?;
        if table.duplicates() > 0 {
            eprintln!(
                "note: {path}: {} duplicate key(s); the last occurrence is used",
                table.duplicates()
            );
        }
        rules.push(EnrichRule {
            column,
            name,
            provider: Provider::Lookup(Arc::new(table)),
        });
    }
    Ok(Some(Enrichment::new(dialect, rules)))
}

/// Header names followed by the derived column names, for resolving `-c`.
fn all_column_names<'a>(
    header: Option<&[Cow<'a, [u8]>]>,
    enrichment: Option<&Enrichment>,
) -> Vec<Cow<'a, [u8]>> {
    let mut names: Vec<Cow<'a, [u8]>> = header.map(|h| h.to_vec()).unwrap_or_default();
    if let Some(e) = enrichment {
        names.extend(
            e.derived_names()
                .into_iter()
                .map(|n| Cow::Owned(n.into_bytes())),
        );
    }
    names
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum HashAlgo {
    Sha256,
    Blake3,
    All,
    None,
}

impl From<HashAlgo> for HashSelection {
    fn from(a: HashAlgo) -> Self {
        match a {
            HashAlgo::Sha256 => HashSelection::SHA256,
            HashAlgo::Blake3 => HashSelection {
                sha256: false,
                blake3: true,
            },
            HashAlgo::All => HashSelection::ALL,
            HashAlgo::None => HashSelection::NONE,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    let result = match cli.cmd {
        Cmd::Info {
            file,
            rows,
            dialect,
        } => cmd_info(&file, rows, &dialect, json),
        Cmd::Index {
            file,
            dialect,
            stride_records,
            stride_bytes,
            chunk_size,
            hash,
            index,
            no_fields,
        } => cmd_index(
            &file,
            &dialect,
            IndexOpts {
                stride_records,
                stride_bytes,
                chunk_size,
                hash: hash.into(),
                index_path: index,
                count_fields: !no_fields,
            },
            json,
        ),
        Cmd::Rows {
            file,
            dialect,
            start,
            count,
            index,
            raw,
        } => cmd_rows(&file, &dialect, start, count, index, raw, json),
        Cmd::Search {
            file,
            pattern,
            dialect,
            regex,
            ignore_case,
            column,
            invert,
            show,
            threads,
            index,
        } => cmd_search(
            &file,
            &dialect,
            &pattern,
            SearchArgs {
                regex,
                ignore_case,
                columns: column,
                invert,
                show,
                threads,
                index_path: index,
            },
            json,
        ),
        Cmd::Export {
            file,
            output,
            dialect,
            search,
            regex,
            ignore_case,
            column,
            invert,
            range,
            omit_header,
            crlf,
            force,
            threads,
            index,
            redact,
            hmac_key_file,
            enrich,
        } => cmd_export(
            &file,
            &dialect,
            ExportArgs {
                output,
                search,
                regex,
                ignore_case,
                columns: column,
                invert,
                range,
                omit_header,
                crlf,
                force,
                threads,
                index_path: index,
                redact,
                hmac_key_file,
                enrich,
            },
            json,
        ),
        Cmd::Verify {
            output,
            manifest,
            source,
            skip_source,
        } => cmd_verify(&output, manifest, source, skip_source, json),
        Cmd::Freq {
            file,
            column,
            top,
            dialect,
            search,
            regex,
            ignore_case,
            invert,
            threads,
            index,
            enrich,
        } => cmd_freq(
            &file,
            &dialect,
            FreqArgs {
                column,
                top,
                search,
                regex,
                ignore_case,
                invert,
                threads,
                index_path: index,
                enrich,
            },
            json,
        ),
        Cmd::Timeline {
            file,
            column,
            bucket,
            max_buckets,
            dialect,
            search,
            regex,
            ignore_case,
            invert,
            year,
            threads,
            index,
        } => cmd_timeline(
            &file,
            &dialect,
            TimelineArgs {
                column,
                bucket,
                max_buckets,
                search,
                regex,
                ignore_case,
                invert,
                year,
                threads,
                index_path: index,
            },
            json,
        ),
        Cmd::Profile {
            file,
            dialect,
            index,
        } => cmd_profile(&file, &dialect, index, json),
        Cmd::Count {
            file,
            dialect,
            chunk_size,
        } => cmd_count(&file, &dialect, chunk_size, json),
        Cmd::Hash {
            file,
            algo,
            chunk_size,
        } => cmd_hash(&file, algo.into(), chunk_size, json),
        Cmd::Gen {
            output,
            profile,
            rows,
            size,
            seed,
        } => cmd_gen(&output, profile, rows, size, seed, json),
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// shared helpers

fn open(file: &Path) -> Result<Source> {
    Source::open(file).with_context(|| format!("opening {}", file.display()))
}

/// Sniff the head of the file and apply command-line overrides.
fn resolve_dialect(src: &Source, args: &DialectArgs) -> Result<(Sniff, Dialect)> {
    let head = src.slice(0, 1 << 20);
    let sn = sniff(head, src.len());
    let mut d = sn.dialect;
    if let Some(s) = &args.delimiter {
        d.delimiter = match s.as_str() {
            "tab" | "\\t" => b'\t',
            s if s.len() == 1 => s.as_bytes()[0],
            _ => bail!("delimiter must be a single byte or `tab`"),
        };
    }
    if args.no_quote {
        d.quote = None;
    }
    if args.no_header {
        d.has_header = false;
    }
    if args.header {
        d.has_header = true;
    }
    Ok((sn, d))
}

struct IndexOpts {
    stride_records: u32,
    stride_bytes: u64,
    chunk_size: u64,
    hash: HashSelection,
    index_path: Option<PathBuf>,
    count_fields: bool,
}

fn progress_bar(total: u64, json: bool) -> ProgressBar {
    if json || !io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
        )
        .expect("valid template")
        .progress_chars("=> "),
    );
    pb
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_uppercase() {
                'K' => 1u64 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => return Err(format!("unknown size suffix {c:?}")),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    let n: f64 = num.parse().map_err(|_| format!("invalid size {s:?}"))?;
    if n < 0.0 {
        return Err("size must be positive".into());
    }
    Ok((n * mult as f64) as u64)
}

fn mib_per_s(bytes: u64, d: Duration) -> f64 {
    let s = d.as_secs_f64();
    if s <= 0.0 {
        0.0
    } else {
        bytes as f64 / (1024.0 * 1024.0) / s
    }
}

fn field_str(f: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(f)
}

/// Compact one-line rendering of a record for the terminal.
fn render_fields(fields: &[Cow<'_, [u8]>], max_width: usize) -> String {
    let mut s = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push_str(" | ");
        }
        let t = field_str(f);
        let t = t.replace('\n', "\\n").replace('\r', "\\r");
        if t.chars().count() > max_width {
            let cut: String = t.chars().take(max_width - 1).collect();
            s.push_str(&cut);
            s.push('…');
        } else {
            s.push_str(&t);
        }
    }
    s
}

fn dialect_json(d: &Dialect) -> Value {
    json!({
        "delimiter": (d.delimiter as char).to_string(),
        "quote": d.quote.map(|q| (q as char).to_string()),
        "header": d.has_header,
    })
}

fn print_json(v: &Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// commands

fn cmd_info(file: &Path, rows: usize, args: &DialectArgs, json: bool) -> Result<()> {
    let t0 = Instant::now();
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let idx = bootstrap(&src, params);
    let header = header_fields(&src, &idx);
    let recs = locate_records(&src, &idx, 0, rows);
    let elapsed = t0.elapsed();

    let mut fields = Vec::new();
    if json {
        let records: Vec<Value> = recs
            .iter()
            .map(|r| {
                r.fields(&src, &idx, &mut fields);
                json!({
                    "record": r.record,
                    "start": r.start,
                    "end": r.end,
                    "fields": fields.iter().map(|f| field_str(f)).collect::<Vec<_>>(),
                })
            })
            .collect();
        return print_json(&json!({
            "file": file.display().to_string(),
            "size": src.len(),
            "bom": format!("{:?}", sn.bom).to_lowercase(),
            "dialect": dialect_json(&dialect),
            "sniff": {
                "field_count": sn.field_count,
                "consistency": sn.consistency,
                "sampled_records": sn.sampled_records,
            },
            "header": header.as_ref().map(|h| h.iter().map(|f| field_str(f)).collect::<Vec<_>>()),
            "records": records,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        }));
    }

    println!(
        "File        {} ({})",
        file.display(),
        human_bytes(src.len())
    );
    println!(
        "Dialect     delimiter={:?} quote={} header={}",
        dialect.delimiter as char,
        dialect
            .quote
            .map_or("none".to_string(), |q| format!("{:?}", q as char)),
        if dialect.has_header { "yes" } else { "no" }
    );
    println!(
        "Sniff       {} fields, {:.1}% consistent over {} sampled records, bom={:?}",
        sn.field_count,
        sn.consistency * 100.0,
        sn.sampled_records,
        sn.bom
    );
    if let Some(h) = &header {
        println!("Header      {}", render_fields(h, 24));
    }
    println!("First {} record(s):", recs.len());
    for r in &recs {
        r.fields(&src, &idx, &mut fields);
        println!("  {:>6}  {}", r.record, render_fields(&fields, 32));
    }
    eprintln!(
        "({:.1} ms, peak RSS {})",
        elapsed.as_secs_f64() * 1000.0,
        human_bytes(peak_rss_bytes())
    );
    Ok(())
}

fn cmd_index(file: &Path, args: &DialectArgs, opts: IndexOpts, json: bool) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        stride_records: opts.stride_records,
        stride_bytes: opts.stride_bytes,
    };
    let index_path = match opts.index_path {
        Some(p) => p,
        None => default_index_path(file)?,
    };
    let pb = progress_bar(src.len(), json);
    let t0 = Instant::now();
    let idx = build_index(
        &src,
        params,
        BuildOptions {
            chunk_size: opts.chunk_size as usize,
            hash: opts.hash,
            count_fields: opts.count_fields,
            cancel: None,
        },
        &mut |_, p| pb.set_position(p.bytes),
    )
    .context("indexing")?;
    let elapsed = t0.elapsed();
    pb.finish_and_clear();
    idx.save(&index_path)
        .with_context(|| format!("writing index to {}", index_path.display()))?;
    let index_bytes = fs::metadata(&index_path).map(|m| m.len()).unwrap_or(0);
    let rss = peak_rss_bytes();

    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "size": src.len(),
            "dialect": dialect_json(&dialect),
            "index_path": index_path.display().to_string(),
            "index_bytes": index_bytes,
            "checkpoints": idx.checkpoints.len(),
            "stride_records": params.stride_records,
            "stride_bytes": params.stride_bytes,
            "records": idx.stats.records,
            "expected_fields": idx.stats.expected_fields,
            "field_mismatches": idx.stats.field_mismatches,
            "lenient_quotes": idx.stats.lenient_quotes,
            "unterminated_quotes": idx.stats.unterminated_quotes,
            "max_record_bytes": idx.stats.max_record_bytes,
            "sha256": idx.digests.sha256.map(|d| hex(&d)),
            "blake3": idx.digests.blake3.map(|d| hex(&d)),
            "elapsed_s": elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(src.len(), elapsed),
            "peak_rss_bytes": rss,
        }));
    }
    println!(
        "File        {} ({})",
        file.display(),
        human_bytes(src.len())
    );
    println!(
        "Records     {} ({} fields expected, {} mismatched, {} lenient quotes, {} unterminated)",
        idx.stats.records,
        idx.stats.expected_fields,
        idx.stats.field_mismatches,
        idx.stats.lenient_quotes,
        idx.stats.unterminated_quotes
    );
    println!(
        "Longest     {} record",
        human_bytes(idx.stats.max_record_bytes)
    );
    println!(
        "Index       {} checkpoints, {} on disk ({:.3}% of source) → {}",
        idx.checkpoints.len(),
        human_bytes(index_bytes),
        if !src.is_empty() {
            index_bytes as f64 * 100.0 / src.len() as f64
        } else {
            0.0
        },
        index_path.display()
    );
    if let Some(d) = idx.digests.sha256 {
        println!("SHA-256     {}", hex(&d));
    }
    if let Some(d) = idx.digests.blake3 {
        println!("BLAKE3      {}", hex(&d));
    }
    println!(
        "Time        {:.2} s ({:.0} MiB/s), peak RSS {}",
        elapsed.as_secs_f64(),
        mib_per_s(src.len(), elapsed),
        human_bytes(rss)
    );
    Ok(())
}

fn cmd_rows(
    file: &Path,
    args: &DialectArgs,
    start: u64,
    count: usize,
    index_path: Option<PathBuf>,
    raw: bool,
    json: bool,
) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let path = match index_path {
        Some(p) => p,
        None => default_index_path(file)?,
    };
    let (idx, from_index) = match SparseIndex::load(&path) {
        Ok(idx) if idx.matches_source(src.id()) => (idx, true),
        Ok(_) => {
            eprintln!(
                "warning: index at {} was built for a different version of this file; scanning instead",
                path.display()
            );
            (bootstrap(&src, params), false)
        }
        Err(_) => (bootstrap(&src, params), false),
    };
    // The index knows the dialect it was built with; honour it over the sniff.
    let t0 = Instant::now();
    let cp = idx.locate(start);
    let recs = locate_records(&src, &idx, start, count);
    let elapsed = t0.elapsed();

    let mut fields = Vec::new();
    if json {
        let records: Vec<Value> = recs
            .iter()
            .map(|r| {
                r.fields(&src, &idx, &mut fields);
                json!({
                    "record": r.record,
                    "start": r.start,
                    "end": r.end,
                    "field_count": r.fields,
                    "fields": fields.iter().map(|f| field_str(f)).collect::<Vec<_>>(),
                })
            })
            .collect();
        return print_json(&json!({
            "file": file.display().to_string(),
            "start": start,
            "count": count,
            "from_index": from_index,
            "checkpoint": cp.map(|c| json!({"record": c.record, "offset": c.offset})),
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "records": records,
        }));
    }
    if let Some(h) = header_fields(&src, &idx) {
        println!("{:>10}  {}", "#", render_fields(&h, 24));
    }
    for r in &recs {
        if raw {
            let mut out = io::stdout().lock();
            write!(out, "{:>10}  ", r.record)?;
            out.write_all(r.raw(&src))?;
            out.write_all(b"\n")?;
        } else {
            r.fields(&src, &idx, &mut fields);
            println!("{:>10}  {}", r.record, render_fields(&fields, 32));
        }
    }
    eprintln!(
        "({} record(s) in {:.2} ms via {}, checkpoint {}, peak RSS {})",
        recs.len(),
        elapsed.as_secs_f64() * 1000.0,
        if from_index {
            "index"
        } else {
            "scan from start"
        },
        cp.map_or("none".to_string(), |c| format!(
            "#{}@{}",
            c.record, c.offset
        )),
        human_bytes(peak_rss_bytes())
    );
    Ok(())
}

fn cmd_count(file: &Path, args: &DialectArgs, chunk_size: u64, json: bool) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        stride_records: u32::MAX,
        stride_bytes: u64::MAX,
    };
    let pb = progress_bar(src.len(), json);
    let t0 = Instant::now();
    let idx = build_index(
        &src,
        params,
        BuildOptions {
            chunk_size: chunk_size as usize,
            hash: HashSelection::NONE,
            count_fields: true,
            cancel: None,
        },
        &mut |_, p| pb.set_position(p.bytes),
    )
    .context("scanning")?;
    let elapsed = t0.elapsed();
    pb.finish_and_clear();
    let rss = peak_rss_bytes();
    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "size": src.len(),
            "dialect": dialect_json(&dialect),
            "records": idx.stats.records,
            "expected_fields": idx.stats.expected_fields,
            "field_mismatches": idx.stats.field_mismatches,
            "lenient_quotes": idx.stats.lenient_quotes,
            "unterminated_quotes": idx.stats.unterminated_quotes,
            "max_record_bytes": idx.stats.max_record_bytes,
            "elapsed_s": elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(src.len(), elapsed),
            "peak_rss_bytes": rss,
        }));
    }
    println!("{}", idx.stats.records);
    eprintln!(
        "({} fields expected, {} mismatched, {} lenient quotes, {} unterminated; {:.2} s, {:.0} MiB/s, peak RSS {})",
        idx.stats.expected_fields,
        idx.stats.field_mismatches,
        idx.stats.lenient_quotes,
        idx.stats.unterminated_quotes,
        elapsed.as_secs_f64(),
        mib_per_s(src.len(), elapsed),
        human_bytes(rss)
    );
    Ok(())
}

fn cmd_hash(file: &Path, sel: HashSelection, chunk_size: u64, json: bool) -> Result<()> {
    if sel.is_empty() {
        bail!("no digest selected");
    }
    let src = open(file)?;
    let t0 = Instant::now();
    let d = hash_source(&src, sel, chunk_size as usize, None)?.expect("not cancellable here");
    let elapsed = t0.elapsed();
    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "size": src.len(),
            "sha256": d.sha256.map(|d| hex(&d)),
            "blake3": d.blake3.map(|d| hex(&d)),
            "elapsed_s": elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(src.len(), elapsed),
        }));
    }
    if let Some(x) = d.sha256 {
        println!("sha256  {}  {}", hex(&x), file.display());
    }
    if let Some(x) = d.blake3 {
        println!("blake3  {}  {}", hex(&x), file.display());
    }
    eprintln!(
        "({:.2} s, {:.0} MiB/s)",
        elapsed.as_secs_f64(),
        mib_per_s(src.len(), elapsed)
    );
    Ok(())
}

fn cmd_gen(
    output: &Path,
    profile: Profile,
    rows: Option<u64>,
    size: Option<u64>,
    seed: u64,
    json: bool,
) -> Result<()> {
    let target = match (rows, size) {
        (Some(r), None) => Target::Rows(r),
        (None, Some(s)) => Target::Bytes(s),
        (None, None) => bail!("specify --rows or --size"),
        (Some(_), Some(_)) => unreachable!("clap enforces exclusivity"),
    };
    let f = fs::File::create(output).with_context(|| format!("creating {}", output.display()))?;
    let pb = match target {
        Target::Bytes(n) => progress_bar(n, json),
        Target::Rows(_) => ProgressBar::hidden(),
    };
    let t0 = Instant::now();
    let mut g = Generator::new(profile, seed);
    let stats = g.generate(f, target, Some(&mut |bytes, _| pb.set_position(bytes)))?;
    let elapsed = t0.elapsed();
    pb.finish_and_clear();
    if json {
        return print_json(&json!({
            "output": output.display().to_string(),
            "profile": profile.name(),
            "seed": seed,
            "rows": stats.rows,
            "bytes": stats.bytes,
            "elapsed_s": elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(stats.bytes, elapsed),
        }));
    }
    println!(
        "wrote {} rows, {} to {} ({:.2} s, {:.0} MiB/s, profile={}, seed={})",
        stats.rows,
        human_bytes(stats.bytes),
        output.display(),
        elapsed.as_secs_f64(),
        mib_per_s(stats.bytes, elapsed),
        profile.name(),
        seed
    );
    Ok(())
}

struct SearchArgs {
    regex: bool,
    ignore_case: bool,
    columns: Vec<String>,
    invert: bool,
    show: usize,
    threads: usize,
    index_path: Option<PathBuf>,
}

/// Load the sidecar index if it exists and matches, else bootstrap one.
fn load_index(
    file: &Path,
    src: &Source,
    params: IndexParams,
    index_path: Option<PathBuf>,
) -> Result<(SparseIndex, bool)> {
    let path = match index_path {
        Some(p) => p,
        None => default_index_path(file)?,
    };
    Ok(match SparseIndex::load(&path) {
        Ok(idx) if idx.matches_source(src.id()) => (idx, true),
        Ok(_) => {
            eprintln!(
                "warning: index at {} was built for a different version of this file; ignoring it",
                path.display()
            );
            (bootstrap(src, params), false)
        }
        Err(_) => (bootstrap(src, params), false),
    })
}

/// Resolve `--column` values (header names or 0-based indexes).
fn resolve_columns(
    specs: &[String],
    header: Option<&[Cow<'_, [u8]>]>,
) -> Result<Option<Vec<usize>>> {
    if specs.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::new();
    for s in specs {
        if let Ok(n) = s.parse::<usize>() {
            out.push(n);
            continue;
        }
        let found = header.and_then(|h| h.iter().position(|f| f.as_ref() == s.as_bytes()));
        match found {
            Some(i) => out.push(i),
            None => bail!("unknown column {s:?} (use a header name or a 0-based index)"),
        }
    }
    Ok(Some(out))
}

fn cmd_search(
    file: &Path,
    args: &DialectArgs,
    pattern: &str,
    o: SearchArgs,
    json: bool,
) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let (idx, from_index) = load_index(file, &src, params, o.index_path)?;
    if !from_index && !json {
        eprintln!(
            "note: no index for this file; searching sequentially (run `gridsift index` first for a parallel search)"
        );
    }
    let header = header_fields(&src, &idx);
    let columns = resolve_columns(&o.columns, header.as_deref())?;
    let query = SearchQuery {
        pattern: pattern.to_string(),
        kind: if o.regex {
            PatternKind::Regex
        } else {
            PatternKind::Literal
        },
        case_insensitive: o.ignore_case,
        columns,
        invert: o.invert,
    };
    let compiled = query
        .compile(idx.params.dialect)
        .map_err(|e| anyhow::anyhow!("invalid pattern: {e}"))?;
    let shared = SearchShared::new(src.len());
    let opts = SearchOptions {
        threads: o.threads,
        ..SearchOptions::default()
    };
    let pb = progress_bar(src.len(), json);
    let outcome = std::thread::scope(|s| {
        let h = s.spawn(|| search(&src, &idx, &compiled, opts, &shared));
        while !h.is_finished() {
            pb.set_position(shared.bytes.load(std::sync::atomic::Ordering::Relaxed));
            std::thread::sleep(Duration::from_millis(50));
        }
        h.join().expect("search thread")
    });
    pb.finish_and_clear();
    let matches = shared.matches.lock().expect("match set");
    let first: Vec<u64> = matches.iter().take(o.show).collect();
    let recs = locate_many(&src, &idx, &first);
    let rss = peak_rss_bytes();

    let mut fields = Vec::new();
    if json {
        let records: Vec<Value> = recs
            .iter()
            .map(|r| {
                r.fields(&src, &idx, &mut fields);
                json!({
                    "record": r.record,
                    "start": r.start,
                    "end": r.end,
                    "fields": fields.iter().map(|f| field_str(f)).collect::<Vec<_>>(),
                })
            })
            .collect();
        return print_json(&json!({
            "file": file.display().to_string(),
            "size": src.len(),
            "query": {
                "pattern": query.pattern,
                "regex": o.regex,
                "ignore_case": o.ignore_case,
                "columns": query.columns,
                "invert": o.invert,
            },
            "matches": matches.len(),
            "records_scanned": outcome.records_scanned,
            "complete": outcome.complete,
            "from_index": from_index,
            "threads": outcome.threads,
            "ranges": outcome.ranges,
            "elapsed_s": outcome.elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(outcome.bytes_scanned, outcome.elapsed),
            "peak_rss_bytes": rss,
            "records": records,
        }));
    }
    println!("{} matching record(s)", matches.len());
    if let Some(h) = &header {
        if !recs.is_empty() {
            println!("{:>10}  {}", "#", render_fields(h, 24));
        }
    }
    for r in &recs {
        r.fields(&src, &idx, &mut fields);
        println!("{:>10}  {}", r.record, render_fields(&fields, 32));
    }
    eprintln!(
        "({} records scanned{}; {:.2} s, {:.0} MiB/s, {} thread(s) over {} range(s), peak RSS {})",
        outcome.records_scanned,
        if outcome.complete { "" } else { ", cancelled" },
        outcome.elapsed.as_secs_f64(),
        mib_per_s(outcome.bytes_scanned, outcome.elapsed),
        outcome.threads,
        outcome.ranges,
        human_bytes(rss)
    );
    Ok(())
}

fn parse_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| "expected START:COUNT".to_string())?;
    let first = a
        .trim()
        .replace(['_', ','], "")
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    let count = b
        .trim()
        .replace(['_', ','], "")
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    Ok((first, count))
}

/// Load the sidecar if it is complete and carries the source digest;
/// otherwise build (and save) it now. Exports need both.
fn ensure_full_index(
    file: &Path,
    src: &Source,
    params: IndexParams,
    index_path: Option<PathBuf>,
    json: bool,
) -> Result<SparseIndex> {
    let path = match index_path {
        Some(p) => p,
        None => default_index_path(file)?,
    };
    if let Ok(idx) = SparseIndex::load(&path) {
        if idx.matches_source(src.id()) && idx.stats.complete && idx.digests.sha256.is_some() {
            return Ok(idx);
        }
    }
    if !json {
        eprintln!(
            "indexing {} first (sparse index + SHA-256)…",
            file.display()
        );
    }
    let pb = progress_bar(src.len(), json);
    let idx = build_index(src, params, BuildOptions::default(), &mut |_, p| {
        pb.set_position(p.bytes)
    })
    .context("indexing")?;
    pb.finish_and_clear();
    idx.save(&path)
        .with_context(|| format!("writing index to {}", path.display()))?;
    Ok(idx)
}

/// SHA-256 of a whole file with a progress bar.
fn hash_with_progress(src: &Source, json: bool) -> Result<[u8; 32]> {
    let pb = progress_bar(src.len(), json);
    let mut h = MultiHasher::new(HashSelection::SHA256);
    let mut buf = vec![0u8; 8 << 20];
    let mut off = 0u64;
    while off < src.len() {
        let n = src.read_at(&mut buf, off)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        off += n as u64;
        pb.set_position(off);
    }
    pb.finish_and_clear();
    Ok(h.finalize().sha256.expect("sha256 selected"))
}

struct ExportArgs {
    output: PathBuf,
    search: Option<String>,
    regex: bool,
    ignore_case: bool,
    columns: Vec<String>,
    invert: bool,
    range: Option<(u64, u64)>,
    omit_header: bool,
    crlf: bool,
    force: bool,
    threads: usize,
    index_path: Option<PathBuf>,
    redact: Vec<String>,
    hmac_key_file: Option<PathBuf>,
    enrich: EnrichArgs,
}

/// Parse `COLUMN=METHOD[:PARAM]` into a rule.
fn parse_redact_spec(spec: &str, header: Option<&[Cow<'_, [u8]>]>) -> Result<RedactRule> {
    let (col, rest) = spec
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--redact expects COLUMN=METHOD[:PARAM], got {spec:?}"))?;
    let column = resolve_columns(&[col.to_string()], header)?
        .and_then(|c| c.first().copied())
        .expect("one column");
    let name = header
        .and_then(|h| h.get(column))
        .map(|f| field_str(f).into_owned())
        .unwrap_or_else(|| format!("col{column}"));
    let (method, param) = match rest.split_once(':') {
        Some((m, p)) => (m, Some(p)),
        None => (rest, None),
    };
    let method = match method {
        "drop" => RedactMethod::Drop,
        "mask" => RedactMethod::Mask {
            replacement: param.unwrap_or(DEFAULT_MASK).to_string(),
        },
        "partial" => RedactMethod::Partial {
            keep: param
                .map_or(Ok(3), str::parse)
                .context("partial:KEEP must be a number")?,
            fill: '*',
        },
        "ip" => RedactMethod::IpPrefix {
            bits: param
                .map_or(Ok(24), str::parse)
                .context("ip:BITS must be a number")?,
        },
        "hmac" => RedactMethod::Hmac {
            length: param
                .map_or(Ok(DEFAULT_HMAC_LENGTH), str::parse)
                .context("hmac:LENGTH must be a number")?,
            key_fingerprint: String::new(),
        },
        other => bail!("unknown redaction method {other:?} (drop, mask, partial, ip, hmac)"),
    };
    Ok(RedactRule {
        column,
        name,
        method,
    })
}

/// The HMAC key from `--hmac-key-file` or `GRIDSIFT_HMAC_KEY`, if any.
fn hmac_key(file: Option<&Path>) -> Result<Option<Vec<u8>>> {
    if let Some(p) = file {
        let mut k = fs::read(p).with_context(|| format!("reading HMAC key {}", p.display()))?;
        while k.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            k.pop();
        }
        return Ok(Some(k));
    }
    Ok(
        std::env::var_os("GRIDSIFT_HMAC_KEY")
            .map(|v| v.to_string_lossy().into_owned().into_bytes()),
    )
}

fn cmd_export(file: &Path, args: &DialectArgs, o: ExportArgs, json: bool) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let idx = ensure_full_index(file, &src, params, o.index_path.clone(), json)?;
    let header = header_fields(&src, &idx);

    // optional search → selection
    let mut operations = Vec::new();
    let mut matches: Option<MatchSet> = None;
    if let Some(pattern) = &o.search {
        let columns = resolve_columns(&o.columns, header.as_deref())?;
        let query = SearchQuery {
            pattern: pattern.clone(),
            kind: if o.regex {
                PatternKind::Regex
            } else {
                PatternKind::Literal
            },
            case_insensitive: o.ignore_case,
            columns,
            invert: o.invert,
        };
        let compiled = query
            .compile(idx.params.dialect)
            .map_err(|e| anyhow::anyhow!("invalid pattern: {e}"))?;
        let shared = SearchShared::new(src.len());
        let opts = SearchOptions {
            threads: o.threads,
            ..SearchOptions::default()
        };
        let pb = progress_bar(src.len(), json);
        let outcome = std::thread::scope(|s| {
            let h = s.spawn(|| search(&src, &idx, &compiled, opts, &shared));
            while !h.is_finished() {
                pb.set_position(shared.bytes.load(std::sync::atomic::Ordering::Relaxed));
                std::thread::sleep(Duration::from_millis(50));
            }
            h.join().expect("search thread")
        });
        pb.finish_and_clear();
        if !outcome.complete {
            bail!(
                "search did not complete{}",
                outcome.error.map(|e| format!(": {e}")).unwrap_or_default()
            );
        }
        let m = shared
            .matches
            .into_inner()
            .map_err(|_| anyhow::anyhow!("match set poisoned"))?;
        operations.push(Operation::Search {
            query,
            matches: m.len(),
        });
        matches = Some(m);
    }
    let (selection, selection_info, expected) = match (&matches, o.range) {
        (Some(m), _) => (
            Selection::Matches(m),
            SelectionInfo::Matches { records: m.len() },
            m.len(),
        ),
        (None, Some((first, count))) => (
            Selection::Range { first, count },
            SelectionInfo::Range { first, count },
            count.min(idx.stats.records.saturating_sub(first)),
        ),
        (None, None) => (Selection::All, SelectionInfo::All, idx.stats.records),
    };

    let enrichment = build_enrichment(&o.enrich, idx.params.dialect, header.as_deref())?;
    if let Some(e) = &enrichment {
        operations.push(Operation::Enrich { rules: e.info() });
    }
    let redactor = if o.redact.is_empty() {
        None
    } else {
        let rules = o
            .redact
            .iter()
            .map(|s| parse_redact_spec(s, header.as_deref()))
            .collect::<Result<Vec<_>>>()?;
        let key = hmac_key(o.hmac_key_file.as_deref())?;
        let r = Redactor::new(idx.params.dialect, rules, key.as_deref())
            .map_err(|e| anyhow::anyhow!("redaction: {e}"))?;
        operations.push(Operation::Redact {
            policy: r.policy().clone(),
        });
        Some(r)
    };
    let terminator = if o.crlf {
        Terminator::Crlf
    } else {
        Terminator::Lf
    };
    let opts = ExportOptions {
        include_header: !o.omit_header,
        terminator,
        hash: HashSelection::SHA256,
        overwrite: o.force,
        redactor: redactor.as_ref(),
        enrichment: enrichment.as_ref(),
        ..ExportOptions::default()
    };
    let pb = progress_bar(expected, json);
    let rep = export(&src, &idx, selection, opts, &o.output, &mut |records, _| {
        pb.set_position(records)
    })
    .with_context(|| format!("exporting to {}", o.output.display()))?;
    pb.finish_and_clear();

    // manifest next to the output
    let out_path = fs::canonicalize(&o.output).unwrap_or_else(|_| o.output.clone());
    let manifest = Manifest::new(
        SourceInfo::from_source(
            &src,
            idx.params.dialect,
            idx.digests,
            Some(idx.stats.records),
        ),
        operations,
        selection_info,
        OutputInfo {
            path: out_path.display().to_string(),
            name: out_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            format: "csv".into(),
            content: match (redactor.is_some(), enrichment.is_some()) {
                (false, false) => "raw-records",
                (true, false) => "records-redacted",
                (false, true) => "records-enriched",
                (true, true) => "records-redacted-enriched",
            }
            .into(),
            header: !o.omit_header && idx.header.is_some(),
            terminator: String::from_utf8_lossy(terminator.bytes()).into_owned(),
            records: rep.records,
            size: rep.bytes,
            sha256: rep.digests.sha256.map(|d| hex(&d)),
            blake3: rep.digests.blake3.map(|d| hex(&d)),
        },
    );
    let mpath = Manifest::path_for(&o.output);
    manifest
        .write(&mpath)
        .with_context(|| format!("writing manifest to {}", mpath.display()))?;

    if json {
        return print_json(&json!({
            "output": out_path.display().to_string(),
            "manifest": mpath.display().to_string(),
            "records": rep.records,
            "bytes": rep.bytes,
            "sha256": rep.digests.sha256.map(|d| hex(&d)),
            "source_sha256": idx.digests.sha256.map(|d| hex(&d)),
            "selection": manifest.selection,
            "operations": manifest.operations,
            "elapsed_s": rep.elapsed.as_secs_f64(),
        }));
    }
    println!(
        "Exported    {} record(s), {} → {} ({:.2} s)",
        group_thousands(rep.records),
        human_bytes(rep.bytes),
        o.output.display(),
        rep.elapsed.as_secs_f64()
    );
    if let Some(d) = rep.digests.sha256 {
        println!("SHA-256     {}", hex(&d));
    }
    println!(
        "Source      {}  SHA-256 {}",
        file.display(),
        idx.digests.sha256.map_or("(unknown)".into(), |d| hex(&d))
    );
    println!("Manifest    {}", mpath.display());
    Ok(())
}

fn cmd_verify(
    output: &Path,
    manifest_path: Option<PathBuf>,
    source_override: Option<PathBuf>,
    skip_source: bool,
    json: bool,
) -> Result<()> {
    let mpath = manifest_path.unwrap_or_else(|| Manifest::path_for(output));
    let m =
        Manifest::read(&mpath).with_context(|| format!("reading manifest {}", mpath.display()))?;

    let out_src = open(output)?;
    let out_sha = hex(&hash_with_progress(&out_src, json)?);
    let out_ok =
        m.output.sha256.as_deref() == Some(out_sha.as_str()) && m.output.size == out_src.len();

    let source_path = source_override.unwrap_or_else(|| PathBuf::from(&m.source.path));
    let (source_status, source_sha) = if skip_source {
        ("skipped", None)
    } else if !source_path.exists() {
        ("not found", None)
    } else {
        let s = open(&source_path)?;
        if !json {
            eprintln!(
                "hashing source {} ({})…",
                source_path.display(),
                human_bytes(s.len())
            );
        }
        let sha = hex(&hash_with_progress(&s, json)?);
        let ok = m.source.sha256.as_deref() == Some(sha.as_str()) && m.source.size == s.len();
        (if ok { "ok" } else { "MISMATCH" }, Some(sha))
    };
    let all_ok = out_ok && source_status != "MISMATCH";

    if json {
        print_json(&json!({
            "manifest": mpath.display().to_string(),
            "output": { "path": output.display().to_string(), "status": if out_ok { "ok" } else { "MISMATCH" }, "sha256": out_sha, "expected": m.output.sha256 },
            "source": { "path": source_path.display().to_string(), "status": source_status, "sha256": source_sha, "expected": m.source.sha256 },
            "ok": all_ok,
        }))?;
    } else {
        println!(
            "Output      {}  {}",
            output.display(),
            if out_ok { "ok" } else { "MISMATCH" }
        );
        println!("            sha256 {out_sha}");
        if !out_ok {
            println!(
                "            expected {}",
                m.output.sha256.as_deref().unwrap_or("(none)")
            );
        }
        println!("Source      {}  {}", source_path.display(), source_status);
        if let Some(s) = &source_sha {
            println!("            sha256 {s}");
        }
        println!(
            "Manifest    {} · {} record(s) · {} · {} operation(s)",
            m.created_at,
            group_thousands(m.output.records),
            match &m.selection {
                SelectionInfo::All => "all records".to_string(),
                SelectionInfo::Matches { records } =>
                    format!("{} matches", group_thousands(*records)),
                SelectionInfo::Range { first, count } => format!("range {first}:{count}"),
            },
            m.operations.len()
        );
        for op in &m.operations {
            match op {
                Operation::TimeRange {
                    name,
                    column,
                    from,
                    to,
                    matches,
                } => println!(
                    "            time range {name} (column {column}) in [{from}, {to}) → {} matches",
                    group_thousands(*matches)
                ),
                Operation::Enrich { rules } => {
                    for r in rules {
                        let ds = r.dataset.as_ref().map_or(String::new(), |d| {
                            format!(
                                " from {}{}{}",
                                d.name,
                                d.database_type
                                    .as_ref()
                                    .map_or(String::new(), |t| format!(" ({t})")),
                                d.sha256
                                    .as_ref()
                                    .map_or(String::new(), |s| format!(" sha256 {}…", &s[..16]))
                            )
                        });
                        println!(
                            "            enrich {} (column {}) via {}{ds} → {}",
                            r.name,
                            r.column,
                            r.provider,
                            r.derived.join(", ")
                        );
                    }
                }
                Operation::Redact { policy } => {
                    for r in &policy.rules {
                        let how = match &r.method {
                            RedactMethod::Drop => "dropped".to_string(),
                            RedactMethod::Mask { replacement } => {
                                format!("masked as {replacement:?}")
                            }
                            RedactMethod::Partial { keep, fill } => {
                                format!("first {keep} chars kept, rest {fill:?}")
                            }
                            RedactMethod::IpPrefix { bits } => format!("ip truncated to /{bits}"),
                            RedactMethod::Hmac {
                                length,
                                key_fingerprint,
                            } => {
                                format!("hmac-sha256[{length}] with key {key_fingerprint}")
                            }
                        };
                        println!("            redact {} (column {}): {how}", r.name, r.column);
                    }
                }
                Operation::Search { query, matches } => println!(
                    "            search {:?}{}{}{} → {} matches",
                    query.pattern,
                    if query.kind == PatternKind::Regex {
                        " (regex)"
                    } else {
                        ""
                    },
                    if query.case_insensitive {
                        " (case-insensitive)"
                    } else {
                        ""
                    },
                    if query.invert { " (inverted)" } else { "" },
                    group_thousands(*matches)
                ),
            }
        }
    }
    if !all_ok {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_profile(
    file: &Path,
    args: &DialectArgs,
    index_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let (idx, from_index) = load_index(file, &src, params, index_path)?;
    let header: Vec<String> = match header_fields(&src, &idx) {
        Some(h) => h.iter().map(|f| field_str(f).into_owned()).collect(),
        None => (0..idx.stats.expected_fields)
            .map(|i| format!("col{i}"))
            .collect(),
    };
    let t0 = Instant::now();
    let prof = profile_columns(&src, &idx, &header, ProfileOptions::default());
    let elapsed = t0.elapsed();

    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "sampled_records": prof.sampled_records,
            "spans_file": prof.spans_file,
            "from_index": from_index,
            "columns": prof.columns,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        }));
    }
    println!("  #  column                   type          conf  distinct  maxlen  examples");
    for c in &prof.columns {
        let name: String = if c.name.chars().count() > 24 {
            let cut: String = c.name.chars().take(23).collect();
            format!("{cut}…")
        } else {
            c.name.clone()
        };
        let examples = c
            .examples
            .iter()
            .map(|e| {
                let e = e.replace('\n', "\\n").replace('\r', "\\r");
                if e.chars().count() > 28 {
                    let cut: String = e.chars().take(27).collect();
                    format!("{cut}…")
                } else {
                    e
                }
            })
            .collect::<Vec<_>>()
            .join(" | ");
        println!(
            "{:>3}  {:<24} {:<12} {:>4.0}%  {:>8}  {:>6}  {}",
            c.index,
            name,
            c.detected.name(),
            c.confidence * 100.0,
            c.distinct,
            c.max_len,
            examples
        );
    }
    eprintln!(
        "(sampled {} rows{}, {:.1} ms{})",
        group_thousands(prof.sampled_records),
        if prof.spans_file {
            " across the file"
        } else {
            " from the head only"
        },
        elapsed.as_secs_f64() * 1000.0,
        if from_index {
            ""
        } else {
            "; run `gridsift index` first for a file-wide sample"
        }
    );
    Ok(())
}

struct FreqArgs {
    column: String,
    top: usize,
    search: Option<String>,
    regex: bool,
    ignore_case: bool,
    invert: bool,
    threads: usize,
    index_path: Option<PathBuf>,
    enrich: EnrichArgs,
}

/// Run a whole-record search and return its match set (for `--search` on
/// counting commands).
fn search_matches(
    src: &Source,
    idx: &SparseIndex,
    query: &SearchQuery,
    threads: usize,
    json: bool,
) -> Result<MatchSet> {
    let compiled = query
        .compile(idx.params.dialect)
        .map_err(|e| anyhow::anyhow!("invalid pattern: {e}"))?;
    let shared = SearchShared::new(src.len());
    let opts = SearchOptions {
        threads,
        ..SearchOptions::default()
    };
    let pb = progress_bar(src.len(), json);
    let outcome = std::thread::scope(|s| {
        let h = s.spawn(|| search(src, idx, &compiled, opts, &shared));
        while !h.is_finished() {
            pb.set_position(shared.bytes.load(std::sync::atomic::Ordering::Relaxed));
            std::thread::sleep(Duration::from_millis(50));
        }
        h.join().expect("search thread")
    });
    pb.finish_and_clear();
    if !outcome.complete {
        bail!(
            "search did not complete{}",
            outcome.error.map(|e| format!(": {e}")).unwrap_or_default()
        );
    }
    shared
        .matches
        .into_inner()
        .map_err(|_| anyhow::anyhow!("match set poisoned"))
}

fn cmd_freq(file: &Path, args: &DialectArgs, o: FreqArgs, json: bool) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let (idx, from_index) = load_index(file, &src, params, o.index_path)?;
    if !from_index && !json {
        eprintln!(
            "note: no index for this file; counting sequentially (run `gridsift index` first for a parallel count)"
        );
    }
    let header = header_fields(&src, &idx);
    let enrichment = build_enrichment(&o.enrich, idx.params.dialect, header.as_deref())?;
    let names = all_column_names(header.as_deref(), enrichment.as_ref());
    let column = resolve_columns(std::slice::from_ref(&o.column), Some(&names))?
        .and_then(|c| c.first().copied())
        .expect("one column");
    let column_name = names
        .get(column)
        .map(|f| field_str(f).into_owned())
        .unwrap_or_else(|| format!("col{column}"));

    let matches = match &o.search {
        Some(pattern) => Some(search_matches(
            &src,
            &idx,
            &SearchQuery {
                pattern: pattern.clone(),
                kind: if o.regex {
                    PatternKind::Regex
                } else {
                    PatternKind::Literal
                },
                case_insensitive: o.ignore_case,
                columns: None,
                invert: o.invert,
            },
            o.threads,
            json,
        )?),
        None => None,
    };
    let selection = match &matches {
        Some(m) => Selection::Matches(m),
        None => Selection::All,
    };

    let shared = FrequencyShared::new(src.len());
    let opts = FrequencyOptions {
        column,
        top: o.top,
        threads: o.threads,
        enrichment: enrichment.as_ref(),
        ..FrequencyOptions::default()
    };
    let pb = progress_bar(src.len(), json);
    let result = std::thread::scope(|s| {
        let h = s.spawn(|| frequency(&src, &idx, selection, opts, &shared));
        while !h.is_finished() {
            pb.set_position(shared.bytes.load(std::sync::atomic::Ordering::Relaxed));
            std::thread::sleep(Duration::from_millis(50));
        }
        h.join().expect("frequency thread")
    })
    .context("counting")?;
    pb.finish_and_clear();
    if !result.complete {
        bail!("count did not complete");
    }
    let rss = peak_rss_bytes();
    let share = |n: u64| {
        if result.counted == 0 {
            0.0
        } else {
            n as f64 * 100.0 / result.counted as f64
        }
    };

    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "column": column,
            "column_name": column_name,
            "search": o.search,
            "counted": result.counted,
            "empty": result.empty,
            "distinct": result.distinct,
            "exact": result.exact,
            "error_bound": result.error_bound,
            "top": result.top.iter().map(|e| json!({
                "value": field_str(&e.value),
                "count": e.count,
                "share": share(e.count) / 100.0,
            })).collect::<Vec<_>>(),
            "elapsed_s": result.elapsed.as_secs_f64(),
            "throughput_mib_s": mib_per_s(shared.bytes.load(std::sync::atomic::Ordering::Relaxed), result.elapsed),
            "threads": result.threads,
            "peak_rss_bytes": rss,
        }));
    }
    let width = result
        .top
        .iter()
        .map(|e| field_str(&e.value).chars().count().min(60))
        .max()
        .unwrap_or(5)
        .max(5);
    println!("{:<width$}  {:>14}  {:>7}", column_name, "count", "share");
    for e in &result.top {
        let v = field_str(&e.value)
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        let v: String = if v.chars().count() > 60 {
            let cut: String = v.chars().take(59).collect();
            format!("{cut}…")
        } else {
            v
        };
        println!(
            "{:<width$}  {:>14}  {:>6.2}%",
            v,
            group_thousands(e.count),
            share(e.count)
        );
    }
    eprintln!(
        "({} records, {} empty, {} distinct{}; {:.2} s, {:.0} MiB/s, {} thread(s), peak RSS {})",
        group_thousands(result.counted),
        group_thousands(result.empty),
        group_thousands(result.distinct),
        if result.exact {
            String::new()
        } else {
            format!(
                " (estimated; counts may be under by up to {})",
                group_thousands(result.error_bound)
            )
        },
        result.elapsed.as_secs_f64(),
        mib_per_s(
            shared.bytes.load(std::sync::atomic::Ordering::Relaxed),
            result.elapsed
        ),
        result.threads,
        human_bytes(rss)
    );
    Ok(())
}

struct TimelineArgs {
    column: String,
    bucket: String,
    max_buckets: usize,
    search: Option<String>,
    regex: bool,
    ignore_case: bool,
    invert: bool,
    year: Option<i64>,
    threads: usize,
    index_path: Option<PathBuf>,
}

/// `auto`, or a number with an `s`/`m`/`h`/`d` suffix, in seconds.
fn parse_bucket(spec: &str) -> Result<Option<i64>> {
    let s = spec.trim().to_ascii_lowercase();
    if s == "auto" {
        return Ok(None);
    }
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s.as_str(), 1),
        _ => bail!("bucket must be `auto` or like `30s`, `5m`, `1h`, `1d`"),
    };
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid bucket {spec:?}"))?;
    if n <= 0 {
        bail!("bucket must be positive");
    }
    Ok(Some(n * mult))
}

fn cmd_timeline(file: &Path, args: &DialectArgs, o: TimelineArgs, json: bool) -> Result<()> {
    let src = open(file)?;
    let (sn, dialect) = resolve_dialect(&src, args)?;
    let params = IndexParams {
        dialect,
        scan_start: sn.scan_start,
        ..IndexParams::default()
    };
    let (idx, from_index) = load_index(file, &src, params, o.index_path)?;
    if !from_index && !json {
        eprintln!(
            "note: no index for this file; scanning sequentially (run `gridsift index` first for a parallel scan)"
        );
    }
    let header = header_fields(&src, &idx);
    let column = resolve_columns(std::slice::from_ref(&o.column), header.as_deref())?
        .and_then(|c| c.first().copied())
        .expect("one column");
    let column_name = header
        .as_ref()
        .and_then(|h| h.get(column))
        .map(|f| field_str(f).into_owned())
        .unwrap_or_else(|| format!("col{column}"));
    let width_spec = parse_bucket(&o.bucket)?;

    let matches = match &o.search {
        Some(pattern) => Some(search_matches(
            &src,
            &idx,
            &SearchQuery {
                pattern: pattern.clone(),
                kind: if o.regex {
                    PatternKind::Regex
                } else {
                    PatternKind::Literal
                },
                case_insensitive: o.ignore_case,
                columns: None,
                invert: o.invert,
            },
            o.threads,
            json,
        )?),
        None => None,
    };
    let selection = match &matches {
        Some(m) => Selection::Matches(m),
        None => Selection::All,
    };

    let shared = FrequencyShared::new(src.len());
    let opts = TimelineOptions {
        column,
        threads: o.threads,
        reference_year: o.year.unwrap_or_else(current_year),
        ..TimelineOptions::default()
    };
    let pb = progress_bar(src.len(), json);
    let t = std::thread::scope(|s| {
        let h = s.spawn(|| timeline(&src, &idx, selection, opts, &shared));
        while !h.is_finished() {
            pb.set_position(shared.bytes.load(std::sync::atomic::Ordering::Relaxed));
            std::thread::sleep(Duration::from_millis(50));
        }
        h.join().expect("timeline thread")
    })
    .context("timeline")?;
    pb.finish_and_clear();
    if !t.complete {
        bail!("timeline did not complete");
    }
    let width = width_spec.unwrap_or_else(|| t.auto_width(o.max_buckets));
    let buckets = t.rebucket(width);
    let fmt = |secs: i64| {
        if secs < 0 {
            format!("{secs}")
        } else {
            iso8601_utc(secs as u64)
        }
    };

    if json {
        return print_json(&json!({
            "file": file.display().to_string(),
            "column": column,
            "column_name": column_name,
            "search": o.search,
            "counted": t.counted,
            "parsed": t.parsed,
            "unparsed": t.unparsed,
            "min": t.min.map(fmt),
            "max": t.max.map(fmt),
            "base_resolution_s": t.resolution,
            "bucket_s": width,
            "buckets": buckets.iter().map(|&(s, c)| json!({"start": fmt(s), "start_unix": s, "count": c})).collect::<Vec<_>>(),
            "elapsed_s": t.elapsed.as_secs_f64(),
            "threads": t.threads,
        }));
    }
    println!(
        "{column_name}: {} parsed, {} unparseable · {} … {} · bucket {}",
        group_thousands(t.parsed),
        group_thousands(t.unparsed),
        t.min.map_or("-".into(), fmt),
        t.max.map_or("-".into(), fmt),
        human_duration(width)
    );
    let max = buckets.iter().map(|b| b.1).max().unwrap_or(1).max(1);
    for (start, count) in &buckets {
        let bar = "█".repeat((count * 40 / max) as usize);
        println!("{}  {:>12}  {bar}", fmt(*start), group_thousands(*count));
    }
    eprintln!(
        "({} records, {:.2} s, {} thread(s){})",
        group_thousands(t.counted),
        t.elapsed.as_secs_f64(),
        t.threads,
        if t.resolution > 1 {
            format!(
                "; base resolution coarsened to {}",
                human_duration(t.resolution)
            )
        } else {
            String::new()
        }
    );
    Ok(())
}

fn human_duration(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}
