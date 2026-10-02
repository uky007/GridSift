//! Cached whole-file analyses: the column profile, value counts and
//! timelines computed over all records of a file, kept in the user's cache
//! directory next to the index sidecar so that the next open of the same
//! bytes shows its charts without a scan.
//!
//! Only whole-file results are cached. Counts over a selection or of a
//! derived (enrichment) column are rarely repeated and would need the whole
//! lineage as their key, so they are recomputed. The cache is bound to the
//! source's size and modification time, and to its SHA-256 when both sides
//! know it; a file that changed gets nothing from it.
//!
//! Timelines are large (one bucket per second over the file's span) and
//! rarely wanted by whoever asks for a count, so they live in a companion
//! file (`.gstl` beside the `.gsan`) that is read only when a timeline is
//! asked for; the profile and the counts stay small and load with the file.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dialect::Dialect;
use crate::frequency::FrequencyResult;
use crate::semantic::Profile;
use crate::sidecar;
use crate::source::{Source, SourceId};
use crate::timeline::TimelineResult;

/// Format version; a cache written by another version is ignored.
pub const VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisCache {
    pub version: u32,
    /// Size and modification time of the source the results came from.
    pub size: u64,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    /// SHA-256 of the source, lowercase hex, when it was known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The file-wide column profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// Value counts over all records, one per column.
    #[serde(default)]
    pub counts: Vec<CachedCount>,
    /// Timelines computed in this session (per column and reference year);
    /// stored in the companion file, not in this one.
    #[serde(skip)]
    pub timelines: Vec<TimelineResult>,
    #[serde(skip)]
    timelines_changed: bool,
}

/// The companion file: the timelines, bound to the same bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TimelineFile {
    version: u32,
    size: u64,
    mtime_secs: u64,
    mtime_nanos: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default)]
    timelines: Vec<TimelineResult>,
}

impl TimelineFile {
    fn matches(&self, id: SourceId, sha256: Option<&str>) -> bool {
        self.version == VERSION
            && self.size == id.size
            && self.mtime_secs == id.mtime_secs
            && self.mtime_nanos == id.mtime_nanos
            && match (&self.sha256, sha256) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedCount {
    /// How many top values were asked for; the entry serves requests up to
    /// that many (or any number when the list is already complete).
    pub top: usize,
    pub result: FrequencyResult,
}

impl AnalysisCache {
    pub fn new(id: SourceId, sha256: Option<String>) -> AnalysisCache {
        AnalysisCache {
            version: VERSION,
            size: id.size,
            mtime_secs: id.mtime_secs,
            mtime_nanos: id.mtime_nanos,
            sha256,
            profile: None,
            counts: Vec::new(),
            timelines: Vec::new(),
            timelines_changed: false,
        }
    }

    /// The companion file holding the timelines of the cache at `path`.
    pub fn timelines_path(path: &Path) -> PathBuf {
        path.with_extension("gstl")
    }

    /// Default location: the user's cache directory, keyed like the index
    /// sidecar by canonical path and parser settings.
    pub fn default_path(source: &Path, dialect: Dialect) -> io::Result<PathBuf> {
        sidecar::default_analysis_path(source, dialect)
    }

    /// The cache describes these bytes: same size and modification time,
    /// and the same SHA-256 when both sides know it.
    pub fn matches(&self, id: SourceId, sha256: Option<&str>) -> bool {
        self.version == VERSION
            && self.size == id.size
            && self.mtime_secs == id.mtime_secs
            && self.mtime_nanos == id.mtime_nanos
            && match (&self.sha256, sha256) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    /// Read a cache file; a missing or unreadable one is simply absent.
    pub fn load(path: &Path) -> Option<AnalysisCache> {
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    /// Read the cache file if it describes these bytes.
    pub fn load_for(path: &Path, id: SourceId, sha256: Option<&str>) -> Option<AnalysisCache> {
        Self::load(path).filter(|c| c.matches(id, sha256))
    }

    /// Learn the digest once it is known, so later loads can check it.
    pub fn set_sha256(&mut self, sha256: String) {
        self.sha256 = Some(sha256);
    }

    pub fn is_empty(&self) -> bool {
        self.profile.is_none() && self.counts.is_empty() && self.timelines.is_empty()
    }

    /// The timeline of `column` for `reference_year` from the companion
    /// file of the cache at `path`, if that file describes these bytes.
    pub fn load_timeline(
        path: &Path,
        id: SourceId,
        sha256: Option<&str>,
        column: usize,
        reference_year: i64,
    ) -> Option<TimelineResult> {
        let bytes = fs::read(Self::timelines_path(path)).ok()?;
        let file: TimelineFile = serde_json::from_slice(&bytes).ok()?;
        if !file.matches(id, sha256) {
            return None;
        }
        file.timelines
            .into_iter()
            .find(|t| t.column == column && t.reference_year == reference_year)
    }

    /// The cached count of `column`, cut to `top` values, if the cached
    /// entry was asked for at least that many (or holds the complete list).
    pub fn count(&self, column: usize, top: usize) -> Option<FrequencyResult> {
        let c = self.counts.iter().find(|c| c.result.column == column)?;
        let complete_list = c.result.top.len() < c.top;
        if c.top < top && !complete_list {
            return None;
        }
        let mut r = c.result.clone();
        r.top.truncate(top);
        Some(r)
    }

    /// Remember a complete count asked for `top` values; a wider request
    /// replaces a narrower one for the same column, never the reverse.
    pub fn put_count(&mut self, top: usize, result: FrequencyResult) {
        if !result.complete {
            return;
        }
        match self
            .counts
            .iter_mut()
            .find(|c| c.result.column == result.column)
        {
            Some(c) if top >= c.top => {
                c.top = top;
                c.result = result;
            }
            Some(_) => {}
            None => self.counts.push(CachedCount { top, result }),
        }
    }

    /// A timeline computed in this session (the companion file is read by
    /// [`AnalysisCache::load_timeline`]).
    pub fn timeline(&self, column: usize, reference_year: i64) -> Option<&TimelineResult> {
        self.timelines
            .iter()
            .find(|t| t.column == column && t.reference_year == reference_year)
    }

    pub fn put_timeline(&mut self, result: TimelineResult) {
        if !result.complete {
            return;
        }
        self.timelines_changed = true;
        match self
            .timelines
            .iter_mut()
            .find(|t| t.column == result.column && t.reference_year == result.reference_year)
        {
            Some(t) => *t = result,
            None => self.timelines.push(result),
        }
    }

    /// Remember the file-wide profile (one drawn from the whole file, not
    /// from the first rows).
    pub fn put_profile(&mut self, profile: Profile) {
        if profile.spans_file {
            self.profile = Some(profile);
        }
    }

    /// Write the cache (temp file + rename) after checking that neither the
    /// target nor its temporary file is the source. Timelines computed in
    /// this session go to the companion file, merged with the ones already
    /// there for the same bytes.
    pub fn save_for(&mut self, source: &Source, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        write_atomically(source, path, &bytes)?;
        if self.timelines_changed {
            let tpath = Self::timelines_path(path);
            let id = SourceId {
                size: self.size,
                mtime_secs: self.mtime_secs,
                mtime_nanos: self.mtime_nanos,
            };
            let mut file = fs::read(&tpath)
                .ok()
                .and_then(|b| serde_json::from_slice::<TimelineFile>(&b).ok())
                .filter(|f| f.matches(id, self.sha256.as_deref()))
                .unwrap_or(TimelineFile {
                    version: VERSION,
                    size: self.size,
                    mtime_secs: self.mtime_secs,
                    mtime_nanos: self.mtime_nanos,
                    sha256: self.sha256.clone(),
                    timelines: Vec::new(),
                });
            file.sha256 = self.sha256.clone().or(file.sha256);
            for t in &self.timelines {
                match file
                    .timelines
                    .iter_mut()
                    .find(|f| f.column == t.column && f.reference_year == t.reference_year)
                {
                    Some(f) => *f = t.clone(),
                    None => file.timelines.push(t.clone()),
                }
            }
            let bytes = serde_json::to_vec(&file).map_err(io::Error::other)?;
            write_atomically(source, &tpath, &bytes)?;
            self.timelines_changed = false;
        }
        Ok(())
    }
}

/// Temp file + rename, refusing a path (or its temporary) that is the source.
fn write_atomically(source: &Source, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = temp_path(path);
    source.guard_not_source(path)?;
    source.guard_not_source(&tmp)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "analysis".into());
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frequency::FrequencyEntry;
    use std::time::Duration;

    fn count(column: usize, values: &[(&str, u64)]) -> FrequencyResult {
        FrequencyResult {
            column,
            counted: values.iter().map(|v| v.1).sum(),
            empty: 0,
            distinct: values.len() as u64,
            exact: true,
            error_bound: 0,
            top: values
                .iter()
                .map(|(v, n)| FrequencyEntry {
                    value: v.as_bytes().to_vec(),
                    count: *n,
                })
                .collect(),
            complete: true,
            elapsed: Duration::from_millis(1),
            threads: 1,
        }
    }

    fn id(size: u64) -> SourceId {
        SourceId {
            size,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 5,
        }
    }

    #[test]
    fn counts_serve_requests_up_to_what_was_asked() {
        let mut c = AnalysisCache::new(id(10), None);
        let twelve: Vec<(String, u64)> = (0..12).map(|i| (format!("v{i}"), 20 - i)).collect();
        let twelve: Vec<(&str, u64)> = twelve.iter().map(|(v, n)| (v.as_str(), *n)).collect();
        c.put_count(12, count(3, &twelve));
        assert_eq!(c.count(3, 5).unwrap().top.len(), 5);
        assert_eq!(c.count(3, 12).unwrap().top.len(), 12);
        assert!(c.count(3, 20).is_none(), "asked for more than was counted");
        assert!(c.count(4, 1).is_none());
        // a narrower request never replaces a wider entry …
        c.put_count(5, count(3, &twelve[..5]));
        assert_eq!(c.count(3, 12).unwrap().top.len(), 12);
        // … a wider one does
        c.put_count(500, count(3, &twelve));
        assert_eq!(
            c.count(3, 1000).unwrap().top.len(),
            12,
            "the list is complete"
        );
        // incomplete results are not kept
        let mut partial = count(7, &twelve[..2]);
        partial.complete = false;
        c.put_count(12, partial);
        assert!(c.count(7, 1).is_none());
    }

    #[test]
    fn cache_is_bound_to_the_bytes() {
        let c = AnalysisCache::new(id(10), Some("ab".into()));
        assert!(c.matches(id(10), Some("ab")));
        assert!(
            c.matches(id(10), None),
            "an unknown digest is not a mismatch"
        );
        assert!(!c.matches(id(11), Some("ab")));
        assert!(!c.matches(id(10), Some("cd")));
        let mut other_time = id(10);
        other_time.mtime_nanos = 6;
        assert!(!c.matches(other_time, Some("ab")));
        let unknown = AnalysisCache::new(id(10), None);
        assert!(unknown.matches(id(10), Some("ab")));
    }

    #[test]
    fn round_trip_through_the_file_and_the_source_guard() {
        let dir = std::env::temp_dir().join(format!("gridsift-analysis-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let src_path = dir.join("src.csv");
        fs::write(&src_path, "a,b\n1,2\n").unwrap();
        let src = Source::open(&src_path).unwrap();
        let mut c = AnalysisCache::new(src.id(), None);
        c.put_count(10, count(1, &[("2", 1)]));
        c.put_timeline(TimelineResult {
            column: 0,
            reference_year: 2026,
            counted: 1,
            parsed: 1,
            unparsed: 0,
            resolution: 1,
            buckets: vec![(0, 1)],
            min: Some(0),
            max: Some(0),
            complete: true,
            elapsed: Duration::from_millis(1),
            threads: 1,
        });
        let path = dir.join("cache").join("src.csv.key.gsan");
        c.save_for(&src, &path).unwrap();
        let back = AnalysisCache::load_for(&path, src.id(), None).expect("same bytes");
        assert_eq!(back.count(1, 10).unwrap().top[0].value, b"2");
        // timelines live in the companion file, read on demand
        assert!(back.timelines.is_empty());
        assert!(AnalysisCache::timelines_path(&path).is_file());
        let t = AnalysisCache::load_timeline(&path, src.id(), None, 0, 2026).unwrap();
        assert_eq!(t.buckets, [(0, 1)]);
        assert!(
            AnalysisCache::load_timeline(&path, src.id(), None, 0, 2027).is_none(),
            "another year parses differently"
        );
        let mut changed = src.id();
        changed.size += 1;
        assert!(AnalysisCache::load_for(&path, changed, None).is_none());
        assert!(AnalysisCache::load_timeline(&path, changed, None, 0, 2026).is_none());
        // a later session adds another column's timeline without losing this one
        let mut later = AnalysisCache::load_for(&path, src.id(), None).unwrap();
        later.put_timeline(TimelineResult {
            column: 1,
            reference_year: 2026,
            counted: 1,
            parsed: 1,
            unparsed: 0,
            resolution: 1,
            buckets: vec![(5, 1)],
            min: Some(5),
            max: Some(5),
            complete: true,
            elapsed: Duration::from_millis(1),
            threads: 1,
        });
        later.save_for(&src, &path).unwrap();
        assert!(AnalysisCache::load_timeline(&path, src.id(), None, 0, 2026).is_some());
        assert_eq!(
            AnalysisCache::load_timeline(&path, src.id(), None, 1, 2026)
                .unwrap()
                .buckets,
            [(5, 1)]
        );
        // never over the evidence
        assert!(c.save_for(&src, &src_path).is_err());
        assert_eq!(fs::read(&src_path).unwrap(), b"a,b\n1,2\n");
    }
}
