//! Semantic column typing: what kind of thing does a column hold?
//!
//! Every value is classified by a chain of cheap byte-level checks (most
//! specific first), and a column takes the plurality label of its non-empty
//! sampled values with the share as confidence. This is inference over a
//! sample, presented as an annotation: values are never converted, and the
//! profile carries the evidence (sample size, share, examples) so an analyst
//! can disagree.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::index::SparseIndex;
use crate::reader::{locate_many, locate_records};
use crate::source::Source;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticType {
    Empty,
    Ipv4,
    Ipv6,
    /// `ip:port` or `[ipv6]:port`
    IpPort,
    Mac,
    Uuid,
    Sha256,
    Sha1,
    Md5,
    Email,
    Url,
    Timestamp,
    Domain,
    Boolean,
    Integer,
    Float,
    /// Integer column whose header mentions a port.
    Port,
    /// Integer column whose header mentions a status, values 100..=599.
    HttpStatus,
    /// Text with few distinct values.
    Categorical,
    Text,
}

impl SemanticType {
    pub fn name(&self) -> &'static str {
        match self {
            SemanticType::Empty => "empty",
            SemanticType::Ipv4 => "ipv4",
            SemanticType::Ipv6 => "ipv6",
            SemanticType::IpPort => "ip:port",
            SemanticType::Mac => "mac",
            SemanticType::Uuid => "uuid",
            SemanticType::Sha256 => "sha256",
            SemanticType::Sha1 => "sha1",
            SemanticType::Md5 => "md5",
            SemanticType::Email => "email",
            SemanticType::Url => "url",
            SemanticType::Timestamp => "timestamp",
            SemanticType::Domain => "domain",
            SemanticType::Boolean => "boolean",
            SemanticType::Integer => "integer",
            SemanticType::Float => "float",
            SemanticType::Port => "port",
            SemanticType::HttpStatus => "http_status",
            SemanticType::Categorical => "categorical",
            SemanticType::Text => "text",
        }
    }

    /// Types that are indicators in security data (enrichable / pivotable).
    pub fn is_indicator(&self) -> bool {
        matches!(
            self,
            SemanticType::Ipv4
                | SemanticType::Ipv6
                | SemanticType::IpPort
                | SemanticType::Mac
                | SemanticType::Sha256
                | SemanticType::Sha1
                | SemanticType::Md5
                | SemanticType::Email
                | SemanticType::Url
                | SemanticType::Domain
        )
    }
}

/// Classify one value. `Text` is the fallback; `Categorical`, `Port` and
/// `HttpStatus` are column-level decisions and never returned here.
pub fn classify_value(v: &[u8]) -> SemanticType {
    let v = trim(v);
    if v.is_empty() {
        return SemanticType::Empty;
    }
    if v.len() > 4096 {
        return SemanticType::Text;
    }
    if is_ipv4(v) {
        return SemanticType::Ipv4;
    }
    if is_ipv6(v) {
        return SemanticType::Ipv6;
    }
    if is_ip_port(v) {
        return SemanticType::IpPort;
    }
    if is_mac(v) {
        return SemanticType::Mac;
    }
    if is_uuid(v) {
        return SemanticType::Uuid;
    }
    if v.iter().all(u8::is_ascii_hexdigit) {
        match v.len() {
            64 => return SemanticType::Sha256,
            40 => return SemanticType::Sha1,
            32 => return SemanticType::Md5,
            _ => {}
        }
    }
    if is_integer(v) {
        return SemanticType::Integer;
    }
    if is_float(v) {
        return SemanticType::Float;
    }
    if is_boolean(v) {
        return SemanticType::Boolean;
    }
    if is_timestamp(v) {
        return SemanticType::Timestamp;
    }
    if is_url(v) {
        return SemanticType::Url;
    }
    if is_email(v) {
        return SemanticType::Email;
    }
    if is_domain(v) {
        return SemanticType::Domain;
    }
    SemanticType::Text
}

fn trim(v: &[u8]) -> &[u8] {
    let s = v
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(v.len());
    let e = v
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(s, |p| p + 1);
    &v[s..e.max(s)]
}

fn as_str(v: &[u8]) -> Option<&str> {
    std::str::from_utf8(v).ok()
}

fn is_ipv4(v: &[u8]) -> bool {
    v.len() <= 15
        && v.iter().all(|b| b.is_ascii_digit() || *b == b'.')
        && as_str(v).is_some_and(|s| Ipv4Addr::from_str(s).is_ok())
}

fn is_ipv6(v: &[u8]) -> bool {
    v.len() <= 45
        && v.iter().filter(|b| **b == b':').count() >= 2
        && as_str(v).is_some_and(|s| Ipv6Addr::from_str(s).is_ok())
}

fn is_ip_port(v: &[u8]) -> bool {
    let Some(p) = v.iter().rposition(|b| *b == b':') else {
        return false;
    };
    let (host, port) = (&v[..p], &v[p + 1..]);
    if port.is_empty() || port.len() > 5 || !port.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if as_str(port)
        .and_then(|s| s.parse::<u32>().ok())
        .is_none_or(|n| n > 65535)
    {
        return false;
    }
    if host.len() >= 2 && host[0] == b'[' && host[host.len() - 1] == b']' {
        is_ipv6(&host[1..host.len() - 1])
    } else {
        is_ipv4(host)
    }
}

fn is_mac(v: &[u8]) -> bool {
    if v.len() != 17 {
        return false;
    }
    let sep = v[2];
    if sep != b':' && sep != b'-' {
        return false;
    }
    v.iter().enumerate().all(|(i, b)| {
        if i % 3 == 2 {
            *b == sep
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

fn is_uuid(v: &[u8]) -> bool {
    v.len() == 36
        && v.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn is_integer(v: &[u8]) -> bool {
    let digits = match v[0] {
        b'-' | b'+' => &v[1..],
        _ => v,
    };
    !digits.is_empty() && digits.len() <= 19 && digits.iter().all(u8::is_ascii_digit)
}

fn is_float(v: &[u8]) -> bool {
    v.len() <= 64
        && v.iter().any(|b| matches!(b, b'.' | b'e' | b'E'))
        && v.iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        && as_str(v).is_some_and(|s| s.parse::<f64>().is_ok_and(f64::is_finite))
}

fn is_boolean(v: &[u8]) -> bool {
    v.len() <= 5
        && matches!(
            v.to_ascii_lowercase().as_slice(),
            b"true" | b"false" | b"yes" | b"no" | b"t" | b"f" | b"y" | b"n"
        )
}

fn timestamp_regex() -> &'static regex::bytes::RegexSet {
    static RE: OnceLock<regex::bytes::RegexSet> = OnceLock::new();
    RE.get_or_init(|| {
        regex::bytes::RegexSet::new([
            // ISO 8601 / RFC 3339, date-only allowed
            r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}([.,]\d{1,9})?)?)?(Z|[+-]\d{2}:?\d{2})?$",
            r"^\d{4}/\d{2}/\d{2}( \d{2}:\d{2}(:\d{2}([.,]\d{1,9})?)?)?(Z|[+-]\d{2}:?\d{2})?$",
            // Apache / CLF
            r"^\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}( [+-]\d{4})?$",
            // syslog
            r"^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}$",
            // US style
            r"^\d{1,2}/\d{1,2}/\d{4}( \d{1,2}:\d{2}(:\d{2})?( ?[AaPp][Mm])?)?$",
            // Windows event style
            r"^\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M$",
        ])
        .expect("valid timestamp patterns")
    })
}

fn is_timestamp(v: &[u8]) -> bool {
    v.len() <= 40 && v[0].is_ascii_alphanumeric() && timestamp_regex().is_match(v)
}

fn is_url(v: &[u8]) -> bool {
    let Some(p) = v.windows(3).position(|w| w == b"://") else {
        return false;
    };
    (2..=16).contains(&p)
        && v[0].is_ascii_alphabetic()
        && v[..p]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        && v.len() > p + 3
        && !v.iter().any(|b| b.is_ascii_whitespace())
}

fn is_email(v: &[u8]) -> bool {
    let Some(at) = v.iter().position(|b| *b == b'@') else {
        return false;
    };
    let (local, domain) = (&v[..at], &v[at + 1..]);
    !local.is_empty()
        && local.len() <= 64
        && local
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
        && is_domain(domain)
}

/// Extensions that look like TLDs but are far more often file names.
const NOT_TLDS: &[&[u8]] = &[
    b"exe", b"dll", b"txt", b"csv", b"log", b"json", b"xml", b"html", b"htm", b"js", b"css",
    b"png", b"jpg", b"jpeg", b"gif", b"svg", b"ico", b"pdf", b"zip", b"gz", b"tar", b"bin", b"dat",
    b"py", b"rs", b"sys", b"ini", b"cfg", b"conf", b"bat", b"ps1", b"sh", b"vbs", b"jar", b"doc",
    b"docx", b"xls", b"xlsx", b"ppt", b"pptx", b"tmp", b"bak", b"db", b"sqlite", b"so", b"dylib",
    b"lnk", b"msi", b"cab", b"scr", b"pem", b"key", b"crt", b"yaml", b"yml", b"toml", b"md",
    b"rtf", b"mp4", b"mp3", b"wav", b"avi", b"mov",
];

fn is_domain(v: &[u8]) -> bool {
    if v.len() < 4 || v.len() > 253 || !v.contains(&b'.') {
        return false;
    }
    let mut labels = v.split(|b| *b == b'.').peekable();
    let mut count = 0;
    let mut last: &[u8] = b"";
    while let Some(l) = labels.next() {
        if l.is_empty()
            || l.len() > 63
            || l[0] == b'-'
            || l[l.len() - 1] == b'-'
            || !l.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
        count += 1;
        if labels.peek().is_none() {
            last = l;
        }
    }
    count >= 2
        && last.len() >= 2
        && last.iter().all(u8::is_ascii_alphabetic)
        && !NOT_TLDS.contains(&last.to_ascii_lowercase().as_slice())
}

/// Profile of one column.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ColumnProfile {
    pub index: usize,
    pub name: String,
    pub detected: SemanticType,
    /// Share of non-empty sampled values carrying the detected label (0..=1).
    pub confidence: f32,
    pub sampled: u32,
    pub non_empty: u32,
    /// Distinct non-empty values in the sample (capped at `sampled`).
    pub distinct: u32,
    pub max_len: u32,
    /// A few distinct example values.
    pub examples: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub columns: Vec<ColumnProfile>,
    pub sampled_records: u64,
    /// The sample was drawn from positions across the whole file (or the
    /// head was the whole file), not just from the first rows.
    pub spans_file: bool,
}

impl Profile {
    pub fn column(&self, index: usize) -> Option<&ColumnProfile> {
        self.columns.get(index)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProfileOptions {
    /// Rows taken from the start of the file.
    pub head_rows: usize,
    /// Positions spread across the file.
    pub positions: usize,
    /// Consecutive rows read at each position.
    pub rows_per_position: usize,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        ProfileOptions {
            head_rows: 512,
            positions: 48,
            rows_per_position: 32,
        }
    }
}

/// Per-column accumulator.
struct Acc {
    counts: Vec<(SemanticType, u32)>,
    sampled: u32,
    non_empty: u32,
    distinct: HashSet<Vec<u8>>,
    max_len: u32,
    examples: Vec<String>,
    all_ints_in_port_range: bool,
    all_ints_in_status_range: bool,
}

impl Acc {
    fn new() -> Acc {
        Acc {
            counts: Vec::new(),
            sampled: 0,
            non_empty: 0,
            distinct: HashSet::new(),
            max_len: 0,
            examples: Vec::new(),
            all_ints_in_port_range: true,
            all_ints_in_status_range: true,
        }
    }

    fn add(&mut self, v: &[u8]) {
        self.sampled += 1;
        let t = classify_value(v);
        self.max_len = self.max_len.max(v.len().min(u32::MAX as usize) as u32);
        if t == SemanticType::Empty {
            return;
        }
        self.non_empty += 1;
        match self.counts.iter_mut().find(|(k, _)| *k == t) {
            Some((_, n)) => *n += 1,
            None => self.counts.push((t, 1)),
        }
        if t == SemanticType::Integer {
            let n = as_str(trim(v)).and_then(|s| s.parse::<i64>().ok());
            self.all_ints_in_port_range &= n.is_some_and(|n| (0..=65535).contains(&n));
            self.all_ints_in_status_range &= n.is_some_and(|n| (100..=599).contains(&n));
        }
        if self.distinct.len() < 65_536 {
            let tv = trim(v);
            if self.distinct.insert(tv.to_vec()) && self.examples.len() < 3 {
                let s = String::from_utf8_lossy(tv);
                self.examples.push(s.chars().take(60).collect());
            }
        }
    }

    fn finish(self, index: usize, name: &str) -> ColumnProfile {
        let lname = name.to_ascii_lowercase();
        let (mut detected, share) = if self.non_empty == 0 {
            (SemanticType::Empty, 1.0)
        } else {
            let (t, n) = self
                .counts
                .iter()
                .copied()
                .max_by_key(|&(_, n)| n)
                .expect("non-empty has counts");
            (t, n as f32 / self.non_empty as f32)
        };
        if detected == SemanticType::Integer {
            if lname.contains("port") && self.all_ints_in_port_range {
                detected = SemanticType::Port;
            } else if lname.contains("status") && self.all_ints_in_status_range {
                detected = SemanticType::HttpStatus;
            }
        }
        if detected == SemanticType::Text {
            let limit = (self.non_empty as f32 * 0.05).max(10.0) as usize;
            if self.distinct.len() <= limit && self.non_empty >= 20 {
                detected = SemanticType::Categorical;
            }
        }
        ColumnProfile {
            index,
            name: name.to_string(),
            detected,
            confidence: share,
            sampled: self.sampled,
            non_empty: self.non_empty,
            distinct: self.distinct.len() as u32,
            max_len: self.max_len,
            examples: self.examples,
        }
    }
}

/// Profile from already-decoded rows (e.g. the rows a UI has on screen).
pub fn profile_rows<'a>(header: &[String], rows: impl Iterator<Item = &'a [String]>) -> Profile {
    let mut accs: Vec<Acc> = header.iter().map(|_| Acc::new()).collect();
    let mut n = 0u64;
    for row in rows {
        n += 1;
        while accs.len() < row.len() {
            accs.push(Acc::new());
        }
        for (c, acc) in accs.iter_mut().enumerate() {
            acc.add(row.get(c).map_or(b"", |s| s.as_bytes()));
        }
    }
    finish_all(accs, header, n, false)
}

fn finish_all(
    accs: Vec<Acc>,
    header: &[String],
    sampled_records: u64,
    spans_file: bool,
) -> Profile {
    Profile {
        columns: accs
            .into_iter()
            .enumerate()
            .map(|(i, a)| {
                let name = header.get(i).cloned().unwrap_or_else(|| format!("col{i}"));
                a.finish(i, &name)
            })
            .collect(),
        sampled_records,
        spans_file,
    }
}

/// Profile a file by sampling rows from its head and from positions spread
/// across the indexed region.
pub fn profile(
    source: &Source,
    index: &SparseIndex,
    header: &[String],
    opts: ProfileOptions,
) -> Profile {
    let mut accs: Vec<Acc> = header.iter().map(|_| Acc::new()).collect();
    let mut fields = Vec::new();
    let mut n = 0u64;
    let mut add_records = |recs: &[crate::reader::Located], accs: &mut Vec<Acc>| {
        for r in recs {
            r.fields(source, index, &mut fields);
            n += 1;
            while accs.len() < fields.len() {
                accs.push(Acc::new());
            }
            for (c, acc) in accs.iter_mut().enumerate() {
                acc.add(fields.get(c).map_or(b"", |f| f.as_ref()));
            }
        }
    };
    let head = locate_records(source, index, 0, opts.head_rows);
    add_records(&head, &mut accs);

    // positions spread over the indexed region (known record count)
    let total = index.stats.records;
    let mut spans_file = false;
    if total > opts.head_rows as u64 && opts.positions > 0 {
        let mut ordinals = Vec::new();
        for p in 0..opts.positions as u64 {
            let start = opts.head_rows as u64
                + (total - opts.head_rows as u64) * (p + 1) / (opts.positions as u64 + 1);
            for k in 0..opts.rows_per_position as u64 {
                let r = start + k;
                if r < total {
                    ordinals.push(r);
                }
            }
        }
        ordinals.sort_unstable();
        ordinals.dedup();
        let recs = locate_many(source, index, &ordinals);
        spans_file = !recs.is_empty();
        add_records(&recs, &mut accs);
    } else if index.stats.complete && total <= opts.head_rows as u64 {
        // the head was the whole file: nothing was left unsampled
        spans_file = true;
    }
    finish_all(accs, header, n, spans_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use crate::synth::{Generator, Profile as SynthProfile, Target};

    fn c(v: &str) -> SemanticType {
        classify_value(v.as_bytes())
    }

    #[test]
    fn value_classification() {
        use SemanticType::*;
        let cases: &[(&str, SemanticType)] = &[
            ("", Empty),
            ("   ", Empty),
            ("10.0.0.1", Ipv4),
            ("255.255.255.255", Ipv4),
            ("256.1.1.1", Text),
            ("1.2.3", Text),
            ("2001:db8::1", Ipv6),
            ("::1", Ipv6),
            ("fe80::1%en0", Text),
            ("10.0.0.1:443", IpPort),
            ("[2001:db8::1]:8080", IpPort),
            ("10.0.0.1:99999", Text),
            ("00:11:22:aa:bb:cc", Mac),
            ("00-11-22-AA-BB-CC", Mac),
            ("123e4567-e89b-12d3-a456-426614174000", Uuid),
            ("d41d8cd98f00b204e9800998ecf8427e", Md5),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", Sha1),
            (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Sha256,
            ),
            (
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                Sha256,
            ),
            ("42", Integer),
            ("-7", Integer),
            ("+3", Integer),
            ("1234567890", Integer),
            ("3.14", Float),
            ("1e10", Float),
            ("-0.5", Float),
            ("true", Boolean),
            ("No", Boolean),
            ("2026-09-27T12:34:56Z", Timestamp),
            ("2026-09-27 12:34:56.123+09:00", Timestamp),
            ("2026-09-27", Timestamp),
            ("2011/08/10 09:46:59.607825", Timestamp), // Argus / CTU-13 flows
            ("27/Sep/2026:12:34:56 +0900", Timestamp),
            ("Sep 27 12:34:56", Timestamp),
            ("9/27/2026 1:02:03 PM", Timestamp),
            ("https://example.com/path?q=1", Url),
            ("ftp://host", Url),
            ("http://", Text),
            ("alice@example.com", Email),
            ("@example.com", Text),
            ("example.com", Domain),
            ("www.example.co.uk", Domain),
            ("xn--80ak6aa92e.com", Domain),
            ("setup.exe", Text),
            ("Mozilla/5.0", Text),
            ("user0317", Text),
            ("/api/v1/login", Text),
            ("-bad.example", Text),
            ("hello world", Text),
        ];
        for (v, want) in cases {
            assert_eq!(c(v), *want, "value {v:?}");
        }
    }

    #[test]
    fn profile_of_synthetic_log() {
        let mut data = Vec::new();
        Generator::new(SynthProfile::Narrow, 5)
            .generate(&mut data, Target::Rows(20_000), None)
            .unwrap();
        let dir = std::env::temp_dir().join(format!("gridsift-semantic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("narrow.csv");
        std::fs::write(&p, &data).unwrap();
        let src = Source::open(&p).unwrap();
        let idx = build_index(
            &src,
            IndexParams {
                stride_records: 256,
                ..IndexParams::default()
            },
            BuildOptions::default(),
            &mut |_, _| {},
        )
        .unwrap();
        let header: Vec<String> = crate::reader::header_fields(&src, &idx)
            .unwrap()
            .iter()
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect();
        let prof = profile(&src, &idx, &header, ProfileOptions::default());
        assert!(prof.spans_file);
        assert!(prof.sampled_records > 512);
        let by_name = |n: &str| prof.columns.iter().find(|c| c.name == n).unwrap();
        use SemanticType::*;
        for (name, want) in [
            ("timestamp", Timestamp),
            ("src_ip", Ipv4),
            ("dst_ip", Ipv4),
            ("dst_port", Port),
            ("proto", Categorical),
            ("host", Domain),
            ("path", Categorical),
            ("status", HttpStatus),
            ("bytes", Integer),
            ("user", Text),
            ("action", Categorical),
            // the generator only has a handful of agents, so this is categorical
            ("user_agent", Categorical),
            ("sha256", Sha256),
        ] {
            let col = by_name(name);
            assert_eq!(col.detected, want, "column {name}: {col:?}");
            assert!(col.confidence > 0.95, "column {name}: {col:?}");
        }
        assert_eq!(by_name("proto").distinct, 2);
        assert!(by_name("user_agent").non_empty < by_name("user_agent").sampled);
        assert_eq!(by_name("sha256").max_len, 64);
        assert!(!by_name("host").examples.is_empty());

        // the same columns from decoded rows
        let recs = locate_records(&src, &idx, 0, 300);
        let mut fields = Vec::new();
        let rows: Vec<Vec<String>> = recs
            .iter()
            .map(|r| {
                r.fields(&src, &idx, &mut fields);
                fields
                    .iter()
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect()
            })
            .collect();
        let quick = profile_rows(&header, rows.iter().map(Vec::as_slice));
        assert!(!quick.spans_file);
        assert_eq!(quick.sampled_records, 300);
        assert_eq!(quick.column(1).unwrap().detected, Ipv4);
    }

    #[test]
    fn mixed_and_empty_columns() {
        let header = vec!["a".to_string(), "b".to_string()];
        let rows: Vec<Vec<String>> = (0..40)
            .map(|i| {
                vec![
                    if i % 4 == 0 {
                        "10.0.0.1".to_string()
                    } else {
                        format!("host{i}")
                    },
                    String::new(),
                ]
            })
            .collect();
        let p = profile_rows(&header, rows.iter().map(Vec::as_slice));
        assert_eq!(p.columns[0].detected, SemanticType::Text);
        assert!((p.columns[0].confidence - 0.75).abs() < 1e-6);
        assert_eq!(p.columns[1].detected, SemanticType::Empty);
        assert_eq!(p.columns[1].non_empty, 0);
    }
}
