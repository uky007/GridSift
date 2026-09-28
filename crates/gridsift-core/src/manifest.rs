//! Provenance manifest written next to every derived artefact.
//!
//! A manifest ties an output file to the evidence it was derived from: the
//! source identity (size, mtime, SHA-256), the parser configuration, every
//! operation that shaped the selection (queries are stored verbatim so they
//! can be replayed), and the output's own digest. `gridsift verify` checks
//! both digests again later.
//!
//! This is a deliberately small, W3C-PROV-inspired record — entity (source)
//! → activities (operations) → entity (output) — not a full PROV document.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dialect::Dialect;
use crate::enrich::EnrichRuleInfo;
use crate::hash::{Digests, hex};
use crate::redact::RedactionPolicy;
use crate::search::SearchQuery;
use crate::source::{Source, SourceId};
use crate::sys::{iso8601_utc, now_iso8601};

pub const MANIFEST_VERSION: u32 = 1;
pub const MANIFEST_SUFFIX: &str = ".manifest.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub gridsift_manifest: u32,
    pub created_at: String,
    pub tool: ToolInfo,
    pub source: SourceInfo,
    /// In application order.
    pub operations: Vec<Operation>,
    pub selection: SelectionInfo,
    pub output: OutputInfo,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub platform: String,
}

impl ToolInfo {
    pub fn current() -> ToolInfo {
        ToolInfo {
            name: "gridsift".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    /// Lowercase hex; `None` only if the digest was not available.
    pub sha256: Option<String>,
    pub blake3: Option<String>,
    pub mtime: Option<String>,
    pub dialect: DialectInfo,
    /// Data records (header excluded), when the index was complete.
    pub records: Option<u64>,
}

impl SourceInfo {
    pub fn from_source(
        source: &Source,
        dialect: Dialect,
        digests: Digests,
        records: Option<u64>,
    ) -> SourceInfo {
        let path = fs::canonicalize(source.path()).unwrap_or_else(|_| source.path().to_path_buf());
        let id: SourceId = source.id();
        SourceInfo {
            path: path.display().to_string(),
            name: path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            size: source.len(),
            sha256: digests.sha256.map(|d| hex(&d)),
            blake3: digests.blake3.map(|d| hex(&d)),
            mtime: (id.mtime_secs > 0).then(|| iso8601_utc(id.mtime_secs)),
            dialect: dialect.into(),
            records,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DialectInfo {
    pub delimiter: String,
    pub quote: Option<String>,
    pub header: bool,
}

impl From<Dialect> for DialectInfo {
    fn from(d: Dialect) -> Self {
        DialectInfo {
            delimiter: (d.delimiter as char).to_string(),
            quote: d.quote.map(|q| (q as char).to_string()),
            header: d.has_header,
        }
    }
}

/// An operation that shaped the exported selection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    /// A search whose matching records form the selection.
    Search { query: SearchQuery, matches: u64 },
    /// Column redaction applied to the output (no secrets recorded).
    Redact { policy: RedactionPolicy },
    /// Derived columns appended from local datasets (identified by hash).
    Enrich { rules: Vec<EnrichRuleInfo> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectionInfo {
    All,
    Matches { records: u64 },
    Range { first: u64, count: u64 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutputInfo {
    pub path: String,
    pub name: String,
    /// `csv`
    pub format: String,
    /// `raw-records`: each record's bytes exactly as in the source, followed
    /// by `terminator`.
    pub content: String,
    pub header: bool,
    pub terminator: String,
    pub records: u64,
    pub size: u64,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
}

impl Manifest {
    pub fn new(
        source: SourceInfo,
        operations: Vec<Operation>,
        selection: SelectionInfo,
        output: OutputInfo,
    ) -> Manifest {
        Manifest {
            gridsift_manifest: MANIFEST_VERSION,
            created_at: now_iso8601(),
            tool: ToolInfo::current(),
            source,
            operations,
            selection,
            output,
        }
    }

    /// `<output>.manifest.json`, next to the output.
    pub fn path_for(output: &Path) -> PathBuf {
        let mut name = output
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default();
        name.push(MANIFEST_SUFFIX);
        output.with_file_name(name)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialises")
    }

    /// Atomic write (temp file + rename).
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(self.to_json().as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    pub fn read(path: &Path) -> io::Result<Manifest> {
        let text = fs::read_to_string(path)?;
        let m: Manifest = serde_json::from_str(&text).map_err(io::Error::other)?;
        if m.gridsift_manifest != MANIFEST_VERSION {
            return Err(io::Error::other(format!(
                "unsupported manifest version {}",
                m.gridsift_manifest
            )));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::PatternKind;

    #[test]
    fn json_roundtrip_and_shape() {
        let m = Manifest::new(
            SourceInfo {
                path: "/evidence/proxy.csv".into(),
                name: "proxy.csv".into(),
                size: 10,
                sha256: Some("ab".repeat(32)),
                blake3: None,
                mtime: Some("2026-09-27T00:00:00Z".into()),
                dialect: Dialect::default().into(),
                records: Some(3),
            },
            vec![Operation::Search {
                query: SearchQuery {
                    pattern: "beacon".into(),
                    kind: PatternKind::Literal,
                    case_insensitive: true,
                    columns: Some(vec![5]),
                    invert: false,
                },
                matches: 2,
            }],
            SelectionInfo::Matches { records: 2 },
            OutputInfo {
                path: "/out/x.csv".into(),
                name: "x.csv".into(),
                format: "csv".into(),
                content: "raw-records".into(),
                header: true,
                terminator: "\n".into(),
                records: 2,
                size: 99,
                sha256: Some("cd".repeat(32)),
                blake3: None,
            },
        );
        let json = m.to_json();
        assert!(json.contains("\"op\": \"search\""));
        assert!(json.contains("\"kind\": \"literal\""));
        assert!(json.contains("\"kind\": \"matches\""));
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.tool.name, "gridsift");
        assert_eq!(back.source.dialect.delimiter, ",");
    }

    #[test]
    fn write_read_and_path() {
        let dir = std::env::temp_dir().join(format!("gridsift-manifest-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("subset.csv");
        let p = Manifest::path_for(&out);
        assert_eq!(p.file_name().unwrap(), "subset.csv.manifest.json");
        let m = Manifest::new(
            SourceInfo {
                path: String::new(),
                name: String::new(),
                size: 0,
                sha256: None,
                blake3: None,
                mtime: None,
                dialect: Dialect::default().into(),
                records: None,
            },
            vec![],
            SelectionInfo::All,
            OutputInfo {
                path: String::new(),
                name: String::new(),
                format: "csv".into(),
                content: "raw-records".into(),
                header: false,
                terminator: "\n".into(),
                records: 0,
                size: 0,
                sha256: None,
                blake3: None,
            },
        );
        m.write(&p).unwrap();
        assert_eq!(Manifest::read(&p).unwrap(), m);
        assert!(!p.with_extension("json.tmp").exists());
        fs::write(&p, "{\"gridsift_manifest\": 99}").unwrap();
        assert!(Manifest::read(&p).is_err());
    }
}
