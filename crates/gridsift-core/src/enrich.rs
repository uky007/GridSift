//! Offline enrichment: derived columns computed from local data only.
//!
//! Three providers, none of which touches the network:
//! - **GeoIP / ASN** from an MMDB file the analyst imports (MaxMind GeoLite2,
//!   DB-IP Lite, …). Databases are never bundled — their licences differ —
//!   and every result is tied to the exact file used (size, SHA-256,
//!   `database_type`, build epoch) in the manifest.
//! - **Domain** decomposition with the Public Suffix List snapshot compiled
//!   into the `psl` crate: registrable domain (eTLD+1), public suffix,
//!   subdomain labels.
//! - **Lookup** joins against a local CSV (asset inventory, IOC list,
//!   resolver-cache export, analyst mapping) by exact key.
//!
//! Derived columns are named `<source column>.<field>` and are annotations:
//! the source is never modified.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dialect::{Dialect, sniff};
use crate::hash::hex;
use crate::record::{nth_field, split_fields};
use crate::scan::scan_all;
use crate::sys::iso8601_utc;

/// Version of the Public Suffix List snapshot (the `psl` crate release that
/// carries it). A test checks it against `Cargo.lock`.
pub const PSL_VERSION: &str = "2.1.238";

/// Identity of a local dataset used for enrichment; recorded in manifests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetInfo {
    pub name: String,
    pub path: Option<String>,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    /// `mmdb`, `csv` or `psl`.
    pub kind: String,
    /// MMDB `database_type`, e.g. `GeoLite2-City`.
    pub database_type: Option<String>,
    /// MMDB build time.
    pub built: Option<String>,
    /// Snapshot / package version for bundled data.
    pub version: Option<String>,
    /// Rows loaded for a lookup table.
    pub records: Option<u64>,
    /// How a lookup table was joined and parsed (lookup datasets only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<LookupInfo>,
}

/// The settings that determine what a lookup join yields, recorded so the
/// same manifest reproduces the same derived columns: which column of the
/// table was the key, which columns were taken as values, and how the
/// table itself was parsed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupInfo {
    pub key: String,
    pub values: Vec<String>,
    pub delimiter: String,
    pub quote: Option<String>,
    pub header: bool,
}

/// What a GeoIP lookup can yield; fields absent from the database stay `None`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoRecord {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoKind {
    City,
    Country,
    Asn,
}

impl GeoKind {
    pub fn fields(&self) -> &'static [&'static str] {
        match self {
            GeoKind::City => &["country", "city"],
            GeoKind::Country => &["country"],
            GeoKind::Asn => &["asn", "as_org"],
        }
    }

    fn from_database_type(t: &str) -> GeoKind {
        let t = t.to_ascii_lowercase();
        if t.contains("asn") {
            GeoKind::Asn
        } else if t.contains("city") {
            GeoKind::City
        } else {
            GeoKind::Country
        }
    }
}

/// An IP → record provider. Implemented by [`GeoIpDb`]; tests use a mock.
pub trait GeoProvider: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> GeoRecord;
    fn kind(&self) -> GeoKind;
    fn info(&self) -> &DatasetInfo;
}

/// A MaxMind-format database loaded from a file the analyst imported.
pub struct GeoIpDb {
    reader: maxminddb::Reader<Vec<u8>>,
    kind: GeoKind,
    info: DatasetInfo,
}

impl GeoIpDb {
    /// Load and fingerprint an `.mmdb` file.
    pub fn open(path: &Path) -> io::Result<GeoIpDb> {
        let bytes = fs::read(path)?;
        let sha256 = hex(&Sha256::digest(&bytes));
        let size = bytes.len() as u64;
        let reader = maxminddb::Reader::from_source(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        let meta = reader.metadata();
        let kind = GeoKind::from_database_type(&meta.database_type);
        let info = DatasetInfo {
            name: path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: Some(
                fs::canonicalize(path)
                    .unwrap_or_else(|_| path.to_path_buf())
                    .display()
                    .to_string(),
            ),
            size: Some(size),
            sha256: Some(sha256),
            kind: "mmdb".into(),
            database_type: Some(meta.database_type.clone()),
            built: Some(iso8601_utc(meta.build_epoch)),
            version: None,
            records: None,
            lookup: None,
        };
        Ok(GeoIpDb { reader, kind, info })
    }
}

impl GeoProvider for GeoIpDb {
    fn lookup(&self, ip: IpAddr) -> GeoRecord {
        use maxminddb::geoip2;
        let Ok(result) = self.reader.lookup(ip) else {
            return GeoRecord::default();
        };
        match self.kind {
            GeoKind::City => match result.decode::<geoip2::City>() {
                Ok(Some(c)) => GeoRecord {
                    country: c.country.iso_code.map(str::to_string),
                    city: c.city.names.english.map(str::to_string),
                    ..GeoRecord::default()
                },
                _ => GeoRecord::default(),
            },
            GeoKind::Country => match result.decode::<geoip2::Country>() {
                Ok(Some(c)) => GeoRecord {
                    country: c.country.iso_code.map(str::to_string),
                    ..GeoRecord::default()
                },
                _ => GeoRecord::default(),
            },
            GeoKind::Asn => match result.decode::<geoip2::Asn>() {
                Ok(Some(a)) => GeoRecord {
                    asn: a.autonomous_system_number,
                    as_org: a.autonomous_system_organization.map(str::to_string),
                    ..GeoRecord::default()
                },
                _ => GeoRecord::default(),
            },
        }
    }

    fn kind(&self) -> GeoKind {
        self.kind
    }

    fn info(&self) -> &DatasetInfo {
        &self.info
    }
}

/// A local CSV loaded into memory for exact-key joins.
pub struct LookupTable {
    map: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    key_name: String,
    value_names: Vec<String>,
    info: DatasetInfo,
    duplicates: u64,
}

impl LookupTable {
    /// Load `path`; `key` and `values` are header names or 0-based indexes.
    /// An empty `values` means every other column.
    pub fn load(path: &Path, key: &str, values: &[String]) -> io::Result<LookupTable> {
        let bytes = fs::read(path)?;
        let sha256 = hex(&Sha256::digest(&bytes));
        let sn = sniff(&bytes[..bytes.len().min(1 << 20)], bytes.len() as u64);
        let d = sn.dialect;
        let spans = scan_all(d.scan_config(false), &bytes[sn.scan_start as usize..]);
        let base = sn.scan_start as usize;
        let mut fields = Vec::new();
        let mut it = spans.iter();
        let header: Vec<String> = match (d.has_header, it.next()) {
            (true, Some(h)) => {
                split_fields(
                    &bytes[base + h.start as usize..base + h.end as usize],
                    d.delimiter,
                    d.quote,
                    &mut fields,
                );
                fields
                    .iter()
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect()
            }
            (false, Some(first)) => {
                // no header: name columns by index, and treat the first record as data
                split_fields(
                    &bytes[base + first.start as usize..base + first.end as usize],
                    d.delimiter,
                    d.quote,
                    &mut fields,
                );
                it = spans.iter();
                (0..fields.len()).map(|i| format!("col{i}")).collect()
            }
            (_, None) => Vec::new(),
        };
        let resolve = |s: &str| -> io::Result<usize> {
            if let Ok(n) = s.parse::<usize>() {
                return Ok(n);
            }
            header.iter().position(|h| h == s).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: no column {s:?}", path.display()),
                )
            })
        };
        let key_col = resolve(key)?;
        let value_cols: Vec<usize> = if values.is_empty() {
            (0..header.len()).filter(|&i| i != key_col).collect()
        } else {
            values
                .iter()
                .map(|v| resolve(v))
                .collect::<io::Result<Vec<_>>>()?
        };
        let value_names: Vec<String> = value_cols
            .iter()
            .map(|&i| header.get(i).cloned().unwrap_or_else(|| format!("col{i}")))
            .collect();
        let mut map: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
        let mut duplicates = 0u64;
        let mut records = 0u64;
        for s in it {
            records += 1;
            split_fields(
                &bytes[base + s.start as usize..base + s.end as usize],
                d.delimiter,
                d.quote,
                &mut fields,
            );
            let Some(k) = fields.get(key_col) else {
                continue;
            };
            let vals: Vec<Vec<u8>> = value_cols
                .iter()
                .map(|&i| fields.get(i).map(|f| f.to_vec()).unwrap_or_default())
                .collect();
            if map.insert(k.to_vec(), vals).is_some() {
                duplicates += 1;
            }
        }
        let info = DatasetInfo {
            name: path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: Some(
                fs::canonicalize(path)
                    .unwrap_or_else(|_| path.to_path_buf())
                    .display()
                    .to_string(),
            ),
            size: Some(bytes.len() as u64),
            sha256: Some(sha256),
            kind: "csv".into(),
            database_type: None,
            built: None,
            version: None,
            records: Some(records),
            lookup: Some(LookupInfo {
                key: header
                    .get(key_col)
                    .cloned()
                    .unwrap_or_else(|| format!("col{key_col}")),
                values: value_names.clone(),
                delimiter: (d.delimiter as char).to_string(),
                quote: d.quote.map(|q| (q as char).to_string()),
                header: d.has_header,
            }),
        };
        Ok(LookupTable {
            map,
            key_name: header
                .get(key_col)
                .cloned()
                .unwrap_or_else(|| format!("col{key_col}")),
            value_names,
            info,
            duplicates,
        })
    }

    pub fn value_names(&self) -> &[String] {
        &self.value_names
    }

    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Keys that appeared more than once (the last occurrence won).
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    pub fn info(&self) -> &DatasetInfo {
        &self.info
    }

    pub fn get(&self, key: &[u8]) -> Option<&[Vec<u8>]> {
        self.map.get(key).map(Vec::as_slice)
    }
}

#[derive(Clone)]
pub enum Provider {
    GeoIp(Arc<dyn GeoProvider>),
    Domain,
    Lookup(Arc<LookupTable>),
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provider::GeoIp(p) => write!(f, "GeoIp({})", p.info().name),
            Provider::Domain => write!(f, "Domain"),
            Provider::Lookup(t) => write!(f, "Lookup({})", t.info().name),
        }
    }
}

impl Provider {
    pub fn label(&self) -> &'static str {
        match self {
            Provider::GeoIp(_) => "geoip",
            Provider::Domain => "domain",
            Provider::Lookup(_) => "lookup",
        }
    }

    fn fields(&self) -> Vec<String> {
        match self {
            Provider::GeoIp(p) => p.kind().fields().iter().map(|s| s.to_string()).collect(),
            Provider::Domain => vec!["registrable".into(), "suffix".into(), "subdomain".into()],
            Provider::Lookup(t) => t.value_names().to_vec(),
        }
    }

    fn dataset(&self) -> Option<DatasetInfo> {
        match self {
            Provider::GeoIp(p) => Some(p.info().clone()),
            Provider::Domain => Some(DatasetInfo {
                name: "public-suffix-list".into(),
                path: None,
                size: None,
                sha256: None,
                kind: "psl".into(),
                database_type: None,
                built: None,
                version: Some(format!("psl {PSL_VERSION}")),
                records: None,
                lookup: None,
            }),
            Provider::Lookup(t) => Some(t.info().clone()),
        }
    }
}

/// One enrichment: a source column and a provider.
#[derive(Clone, Debug)]
pub struct EnrichRule {
    pub column: usize,
    pub name: String,
    pub provider: Provider,
}

/// Serialisable description of a rule, for the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichRuleInfo {
    pub column: usize,
    pub name: String,
    pub provider: String,
    pub derived: Vec<String>,
    pub dataset: Option<DatasetInfo>,
}

struct Derived {
    name: String,
    rule: usize,
    field: usize,
}

/// A set of rules and the derived columns they produce.
pub struct Enrichment {
    dialect: Dialect,
    rules: Vec<EnrichRule>,
    derived: Vec<Derived>,
}

impl std::fmt::Debug for Enrichment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrichment")
            .field("rules", &self.rules)
            .finish()
    }
}

impl Enrichment {
    pub fn new(dialect: Dialect, rules: Vec<EnrichRule>) -> Enrichment {
        let mut derived = Vec::new();
        for (ri, r) in rules.iter().enumerate() {
            for (fi, f) in r.provider.fields().iter().enumerate() {
                derived.push(Derived {
                    name: format!("{}.{}", r.name, f),
                    rule: ri,
                    field: fi,
                });
            }
        }
        Enrichment {
            dialect,
            rules,
            derived,
        }
    }

    pub fn rules(&self) -> &[EnrichRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.derived.is_empty()
    }

    /// Names of the derived columns, in output order.
    pub fn derived_names(&self) -> Vec<String> {
        self.derived.iter().map(|d| d.name.clone()).collect()
    }

    pub fn derived_count(&self) -> usize {
        self.derived.len()
    }

    pub fn info(&self) -> Vec<EnrichRuleInfo> {
        self.rules
            .iter()
            .map(|r| EnrichRuleInfo {
                column: r.column,
                name: r.name.clone(),
                provider: r.provider.label().into(),
                derived: r
                    .provider
                    .fields()
                    .iter()
                    .map(|f| format!("{}.{}", r.name, f))
                    .collect(),
                dataset: r.provider.dataset(),
            })
            .collect()
    }

    /// All derived values for one record, in output order (empty bytes
    /// where a provider has nothing).
    pub fn compute(&self, raw: &[u8], out: &mut Vec<Vec<u8>>) {
        out.clear();
        for r in &self.rules {
            let value = nth_field(raw, self.dialect.delimiter, self.dialect.quote, r.column);
            let v = value.as_deref().unwrap_or(b"");
            apply(&r.provider, trim(v), out);
        }
    }

    /// One derived value (`index` into [`Enrichment::derived_names`]).
    pub fn value(&self, raw: &[u8], index: usize) -> Vec<u8> {
        let Some(d) = self.derived.get(index) else {
            return Vec::new();
        };
        let r = &self.rules[d.rule];
        let value = nth_field(raw, self.dialect.delimiter, self.dialect.quote, r.column);
        let mut vals = Vec::new();
        apply(
            &r.provider,
            trim(value.as_deref().unwrap_or(b"")),
            &mut vals,
        );
        vals.into_iter().nth(d.field).unwrap_or_default()
    }
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

fn apply(provider: &Provider, value: &[u8], out: &mut Vec<Vec<u8>>) {
    match provider {
        Provider::GeoIp(p) => {
            let rec = std::str::from_utf8(value)
                .ok()
                .and_then(|s| IpAddr::from_str(s).ok())
                .map(|ip| p.lookup(ip))
                .unwrap_or_default();
            for f in p.kind().fields() {
                out.push(match *f {
                    "country" => rec.country.clone().unwrap_or_default().into_bytes(),
                    "city" => rec.city.clone().unwrap_or_default().into_bytes(),
                    "asn" => rec
                        .asn
                        .map(|n| n.to_string())
                        .unwrap_or_default()
                        .into_bytes(),
                    "as_org" => rec.as_org.clone().unwrap_or_default().into_bytes(),
                    _ => Vec::new(),
                });
            }
        }
        Provider::Domain => {
            let lower = value.to_ascii_lowercase();
            let name = lower.strip_suffix(b".").unwrap_or(&lower);
            let (registrable, suffix, subdomain) = match (psl::domain(name), psl::suffix(name)) {
                (Some(d), Some(s)) if s.is_known() => {
                    let reg = d.as_bytes();
                    let sub = name
                        .len()
                        .checked_sub(reg.len() + 1)
                        .map_or(&b""[..], |n| &name[..n]);
                    (reg.to_vec(), s.as_bytes().to_vec(), sub.to_vec())
                }
                _ => (Vec::new(), Vec::new(), Vec::new()),
            };
            out.push(registrable);
            out.push(suffix);
            out.push(subdomain);
        }
        Provider::Lookup(t) => match t.get(value) {
            Some(vals) => out.extend(vals.iter().cloned()),
            None => out.extend(t.value_names().iter().map(|_| Vec::new())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGeo {
        info: DatasetInfo,
        kind: GeoKind,
    }

    impl MockGeo {
        fn shared(kind: GeoKind) -> Arc<dyn GeoProvider> {
            Arc::new(MockGeo {
                info: DatasetInfo {
                    name: "mock.mmdb".into(),
                    path: None,
                    size: Some(1),
                    sha256: Some("00".repeat(32)),
                    kind: "mmdb".into(),
                    database_type: Some("Mock-City".into()),
                    built: Some("2026-09-01T00:00:00Z".into()),
                    version: None,
                    records: None,
                    lookup: None,
                },
                kind,
            })
        }
    }

    impl GeoProvider for MockGeo {
        fn lookup(&self, ip: IpAddr) -> GeoRecord {
            match ip {
                IpAddr::V4(v4) if v4.octets()[0] == 104 => GeoRecord {
                    country: Some("US".into()),
                    city: Some("Ashburn".into()),
                    asn: Some(13335),
                    as_org: Some("Cloudflare, Inc.".into()),
                },
                IpAddr::V6(_) => GeoRecord {
                    country: Some("JP".into()),
                    ..GeoRecord::default()
                },
                _ => GeoRecord::default(),
            }
        }
        fn kind(&self) -> GeoKind {
            self.kind
        }
        fn info(&self) -> &DatasetInfo {
            &self.info
        }
    }

    /// A fresh file per call: tests run in parallel and must not share paths.
    fn lookup_csv() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gridsift-enrich-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("assets.csv");
        fs::write(
            &p,
            "ip,owner,site\n10.1.243.150,alice,\"Tokyo, HQ\"\n10.5.65.5,bob,Osaka\n10.5.65.5,bob2,Osaka2\n",
        )
        .unwrap();
        p
    }

    #[test]
    fn geo_domain_lookup_columns() {
        let table = Arc::new(LookupTable::load(&lookup_csv(), "ip", &[]).unwrap());
        assert_eq!(table.len(), 2);
        assert_eq!(table.duplicates(), 1);
        assert_eq!(table.value_names(), ["owner", "site"]);
        let e = Enrichment::new(
            Dialect::default(),
            vec![
                EnrichRule {
                    column: 1,
                    name: "src_ip".into(),
                    provider: Provider::Lookup(table),
                },
                EnrichRule {
                    column: 2,
                    name: "dst_ip".into(),
                    provider: Provider::GeoIp(MockGeo::shared(GeoKind::City)),
                },
                EnrichRule {
                    column: 2,
                    name: "dst_ip".into(),
                    provider: Provider::GeoIp(MockGeo::shared(GeoKind::Asn)),
                },
                EnrichRule {
                    column: 3,
                    name: "host".into(),
                    provider: Provider::Domain,
                },
            ],
        );
        assert_eq!(
            e.derived_names(),
            [
                "src_ip.owner",
                "src_ip.site",
                "dst_ip.country",
                "dst_ip.city",
                "dst_ip.asn",
                "dst_ip.as_org",
                "host.registrable",
                "host.suffix",
                "host.subdomain"
            ]
        );
        let mut out = Vec::new();
        e.compute(b"t,10.5.65.5,104.55.173.161,www.soorinba.co.uk,x", &mut out);
        let got: Vec<&str> = out
            .iter()
            .map(|v| std::str::from_utf8(v).unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "bob2",
                "Osaka2",
                "US",
                "Ashburn",
                "13335",
                "Cloudflare, Inc.",
                "soorinba.co.uk",
                "co.uk",
                "www"
            ]
        );
        // unknown key / unknown ip / bare registrable domain / ipv6
        e.compute(b"t,10.9.9.9,10.0.0.1,example.com,x", &mut out);
        let got: Vec<&str> = out
            .iter()
            .map(|v| std::str::from_utf8(v).unwrap())
            .collect();
        assert_eq!(got, ["", "", "", "", "", "", "example.com", "com", ""]);
        e.compute(b"t,,2001:db8::1,not_a_domain,x", &mut out);
        let got: Vec<&str> = out
            .iter()
            .map(|v| std::str::from_utf8(v).unwrap())
            .collect();
        assert_eq!(got, ["", "", "JP", "", "", "", "", "", ""]);
        // single derived value agrees with compute
        assert_eq!(
            e.value(b"t,10.1.243.150,1.1.1.1,A.B.Example.ORG.,x", 0),
            b"alice"
        );
        assert_eq!(
            e.value(b"t,10.1.243.150,1.1.1.1,A.B.Example.ORG.,x", 1),
            b"Tokyo, HQ"
        );
        assert_eq!(
            e.value(b"t,10.1.243.150,1.1.1.1,A.B.Example.ORG.,x", 6),
            b"example.org"
        );
        assert_eq!(
            e.value(b"t,10.1.243.150,1.1.1.1,A.B.Example.ORG.,x", 8),
            b"a.b"
        );
        assert_eq!(e.value(b"t", 3), b"");
        // manifest info carries dataset identity, never more
        let info = e.info();
        assert_eq!(info.len(), 4);
        assert_eq!(info[0].provider, "lookup");
        assert_eq!(info[0].dataset.as_ref().unwrap().records, Some(3));
        assert_eq!(
            info[1].dataset.as_ref().unwrap().database_type.as_deref(),
            Some("Mock-City")
        );
        assert_eq!(
            info[3].dataset.as_ref().unwrap().version.as_deref(),
            Some(concat!("psl ", "2.1.238"))
        );
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"sha256\""));
    }

    #[test]
    fn lookup_by_index_and_values() {
        let t = LookupTable::load(&lookup_csv(), "0", &["site".into()]).unwrap();
        assert_eq!(t.value_names(), ["site"]);
        assert_eq!(t.key_name(), "ip");
        assert_eq!(t.get(b"10.1.243.150").unwrap()[0], b"Tokyo, HQ");
        assert!(LookupTable::load(&lookup_csv(), "nope", &[]).is_err());
    }

    #[test]
    fn psl_version_matches_lockfile() {
        let lock =
            fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
        let lock = lock.replace('\r', ""); // CRLF checkouts on Windows
        let needle = format!("name = \"psl\"\nversion = \"{PSL_VERSION}\"");
        assert!(
            lock.contains(&needle),
            "PSL_VERSION must match the psl crate in Cargo.lock"
        );
    }

    #[test]
    fn real_mmdb_if_available() {
        // Optional: point GRIDSIFT_TEST_MMDB at a GeoLite2/DB-IP file to
        // exercise the real reader.
        let Some(p) = std::env::var_os("GRIDSIFT_TEST_MMDB") else {
            return;
        };
        let db = GeoIpDb::open(Path::new(&p)).unwrap();
        assert!(db.info().sha256.as_ref().is_some_and(|s| s.len() == 64));
        let rec = db.lookup("8.8.8.8".parse().unwrap());
        assert!(rec.country.is_some() || rec.asn.is_some(), "{rec:?}");
    }
}
