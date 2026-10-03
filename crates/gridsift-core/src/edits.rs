//! Edits laid over a source: changed cell values and marked rows. They are
//! never written into the file; they live in a version file the analyst
//! names and keeps with the case. The grid shows them, an export can apply
//! them (its manifest then lists every changed cell, the original value by
//! its hash), and a version only loads onto the bytes it was made for.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dialect::Dialect;
use crate::hash::hex;
use crate::record::{split_fields, write_field};
use crate::source::Source;
use crate::sys::iso8601_utc;

/// Format version of the version file. Version 1 (gridsift 0.1.0) did not
/// record the parser settings or require a digest and is refused.
pub const VERSION: u32 = 2;

/// Row mark colours by name; `RowMark::color` is 1-based into this list.
pub const MARK_NAMES: [&str; 6] = ["amber", "blue", "green", "coral", "violet", "teal"];

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EditSet {
    pub version: u32,
    /// The name the analyst saved this version under.
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    /// The bytes the edits were made for.
    #[serde(default)]
    pub source: EditSource,
    /// Changed cells, sorted by record then column.
    #[serde(default)]
    pub cells: Vec<CellEdit>,
    /// Marked rows, sorted by record.
    #[serde(default)]
    pub marks: Vec<RowMark>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EditSource {
    pub name: String,
    pub size: u64,
    /// SHA-256 of the source, lowercase hex. Required: a version is only
    /// ever applied to the bytes it was made for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The parser settings the file was read with. Record ordinals count
    /// data records after the header, so the same bytes read with another
    /// header setting (or delimiter, or quote) put every edit on another row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<EditDialect>,
}

/// The parser settings a version was made with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EditDialect {
    pub delimiter: String,
    pub quote: Option<String>,
    pub has_header: bool,
}

impl From<Dialect> for EditDialect {
    fn from(d: Dialect) -> Self {
        EditDialect {
            delimiter: (d.delimiter as char).to_string(),
            quote: d.quote.map(|q| (q as char).to_string()),
            has_header: d.has_header,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CellEdit {
    /// 0-based data record ordinal.
    pub record: u64,
    pub column: usize,
    /// The new value.
    pub value: String,
    /// What the source holds there.
    pub was: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RowMark {
    pub record: u64,
    /// 1-based index into [`MARK_NAMES`].
    pub color: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What a manifest records about the edits applied to an export: only the
/// cells of records that were written, and no value for a column the same
/// export redacts — the manifest travels with the output and must not
/// carry what the output hides.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EditInfo {
    /// Name of the version the edits came from.
    pub version: String,
    /// The edited cells of the records written.
    pub cells: Vec<CellChange>,
    /// Marked rows in the version (marks are not part of the output).
    pub marks: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CellChange {
    pub record: u64,
    pub column: usize,
    pub name: String,
    /// SHA-256 of the original value's bytes: verifiable, not disclosed.
    pub was_sha256: String,
    /// The value written; absent when the column is redacted in this export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl EditSet {
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.marks.is_empty()
    }

    /// The edits of one record (sorted by column; empty when it has none).
    pub fn cells_for(&self, record: u64) -> &[CellEdit] {
        let lo = self.cells.partition_point(|c| c.record < record);
        let hi = lo + self.cells[lo..].partition_point(|c| c.record == record);
        &self.cells[lo..hi]
    }

    pub fn cell(&self, record: u64, column: usize) -> Option<&CellEdit> {
        self.cells
            .binary_search_by(|c| (c.record, c.column).cmp(&(record, column)))
            .ok()
            .map(|i| &self.cells[i])
    }

    /// Change a cell; the source value itself removes the edit.
    pub fn set_cell(&mut self, record: u64, column: usize, value: String, was: String) {
        let pos = self
            .cells
            .binary_search_by(|c| (c.record, c.column).cmp(&(record, column)));
        match pos {
            Ok(i) if value == was => {
                self.cells.remove(i);
            }
            Ok(i) => self.cells[i].value = value,
            Err(_) if value == was => {}
            Err(i) => self.cells.insert(
                i,
                CellEdit {
                    record,
                    column,
                    value,
                    was,
                },
            ),
        }
    }

    pub fn mark(&self, record: u64) -> Option<&RowMark> {
        self.marks
            .binary_search_by_key(&record, |m| m.record)
            .ok()
            .map(|i| &self.marks[i])
    }

    /// Mark a row with a colour (1-based into [`MARK_NAMES`]); 0 clears.
    pub fn set_mark(&mut self, record: u64, color: u8, note: Option<String>) {
        let pos = self.marks.binary_search_by_key(&record, |m| m.record);
        match pos {
            Ok(i) if color == 0 => {
                self.marks.remove(i);
            }
            Ok(i) => {
                self.marks[i].color = color;
                self.marks[i].note = note;
            }
            Err(_) if color == 0 => {}
            Err(i) => self.marks.insert(
                i,
                RowMark {
                    record,
                    color,
                    note,
                },
            ),
        }
    }

    /// Bind the set to its source — the bytes (size and SHA-256) and the
    /// parser settings they were read with — and name it, before saving.
    pub fn stamp(&mut self, source: &Source, sha256: String, dialect: Dialect, name: String) {
        self.version = VERSION;
        self.name = name;
        self.saved_at = Some(iso8601_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        ));
        self.source = EditSource {
            name: source
                .path()
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            size: source.len(),
            sha256: Some(sha256),
            dialect: Some(dialect.into()),
        };
    }

    /// Whether the set may be applied to a file of `size` bytes with digest
    /// `sha256`, read with `dialect`; the error says what differs. Both
    /// digests must be known: a version is never applied on size alone.
    pub fn check(&self, size: u64, sha256: Option<&str>, dialect: Dialect) -> Result<(), String> {
        let Some(own) = &self.source.sha256 else {
            return Err("the version carries no digest of its source and cannot be trusted".into());
        };
        let Some(sha256) = sha256 else {
            return Err("the SHA-256 of this file is not known yet; wait for it".into());
        };
        if self.source.size != size || own != sha256 {
            return Err(
                "the version was made for a different file (size or SHA-256 differ)".into(),
            );
        }
        if self.source.dialect.as_ref() != Some(&EditDialect::from(dialect)) {
            return Err(
                "the version was made with other parser settings (header, delimiter or quote), \
                 so its row numbers would not match"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<EditSet> {
        let set: EditSet = serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)?;
        if set.version != VERSION {
            return Err(io::Error::other(format!(
                "version file format {} is not supported (this build reads {VERSION})",
                set.version
            )));
        }
        Ok(set)
    }

    /// Write the version file (temp file + rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let tmp = temp_path(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Save after checking that neither the file nor its temporary is the
    /// source.
    pub fn save_for(&self, source: &Source, path: &Path) -> io::Result<()> {
        source.guard_not_source(path)?;
        source.guard_not_source(&temp_path(path))?;
        self.save(path)
    }

    /// Render data record `record` with its edits applied into `out`;
    /// `false` when the record has none (the caller keeps the source bytes).
    /// Edited records are re-rendered field by field, quoted as needed.
    pub fn apply(&self, record: u64, bytes: &[u8], dialect: Dialect, out: &mut Vec<u8>) -> bool {
        let edits = self.cells_for(record);
        if edits.is_empty() {
            return false;
        }
        let mut fields = Vec::new();
        split_fields(bytes, dialect.delimiter, dialect.quote, &mut fields);
        let width = fields.len().max(edits.last().map_or(0, |e| e.column + 1));
        out.clear();
        for i in 0..width {
            if i > 0 {
                out.push(dialect.delimiter);
            }
            let value: &[u8] = match edits.iter().find(|e| e.column == i) {
                Some(e) => e.value.as_bytes(),
                None => fields.get(i).map_or(b"", |f| f.as_ref()),
            };
            write_field(value, dialect.delimiter, dialect.quote, out);
        }
        true
    }

    /// What a manifest records: the cells in `applied` (what the export
    /// wrote, as `(record, column)`), named by `names`, with the value left
    /// out for columns `hidden` says the export redacts.
    pub fn info_applied(
        &self,
        applied: &[(u64, usize)],
        names: &[String],
        hidden: &dyn Fn(usize) -> bool,
    ) -> EditInfo {
        EditInfo {
            version: self.name.clone(),
            cells: applied
                .iter()
                .filter_map(|&(record, column)| self.cell(record, column))
                .map(|c| CellChange {
                    record: c.record,
                    column: c.column,
                    name: names
                        .get(c.column)
                        .cloned()
                        .unwrap_or_else(|| format!("col{}", c.column)),
                    was_sha256: hex(&Sha256::digest(c.was.as_bytes())),
                    value: (!hidden(c.column)).then(|| c.value.clone()),
                })
                .collect(),
            marks: self.marks.len() as u64,
        }
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "edits".into());
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_and_marks_keep_order_and_the_source_value_clears_an_edit() {
        let mut e = EditSet::default();
        e.set_cell(5, 1, "x".into(), "a".into());
        e.set_cell(2, 0, "y".into(), "b".into());
        e.set_cell(2, 3, "z".into(), "c".into());
        let order: Vec<(u64, usize)> = e.cells.iter().map(|c| (c.record, c.column)).collect();
        assert_eq!(order, [(2, 0), (2, 3), (5, 1)]);
        assert_eq!(e.cell(2, 3).unwrap().value, "z");
        e.set_cell(2, 3, "zz".into(), "c".into());
        assert_eq!(e.cell(2, 3).unwrap().value, "zz");
        e.set_cell(2, 3, "c".into(), "c".into());
        assert!(
            e.cell(2, 3).is_none(),
            "typing the source value back is no edit"
        );
        e.set_cell(9, 9, "same".into(), "same".into());
        assert_eq!(e.cells.len(), 2);

        e.set_mark(7, 2, None);
        e.set_mark(1, 1, Some("look".into()));
        assert_eq!(e.marks.iter().map(|m| m.record).collect::<Vec<_>>(), [1, 7]);
        assert_eq!(e.mark(1).unwrap().note.as_deref(), Some("look"));
        e.set_mark(7, 0, None);
        assert!(e.mark(7).is_none());
        assert!(!e.is_empty());
    }

    #[test]
    fn apply_rewrites_only_edited_records_and_quotes_as_needed() {
        let d = Dialect::default();
        let mut e = EditSet::default();
        e.set_cell(1, 1, "has,comma".into(), "b".into());
        e.set_cell(1, 3, "beyond".into(), String::new());
        let mut out = Vec::new();
        assert!(!e.apply(0, b"1,a,x", d, &mut out));
        assert!(e.apply(1, b"2,b,\"q\"", d, &mut out));
        assert_eq!(out, b"2,\"has,comma\",q,beyond");
    }

    #[test]
    fn versions_round_trip_and_bind_to_their_bytes() {
        let dir = std::env::temp_dir().join(format!("gridsift-edits-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let src_path = dir.join("src.csv");
        fs::write(&src_path, "a,b\n1,2\n3,4\n").unwrap();
        let src = Source::open(&src_path).unwrap();
        let d = Dialect::default();
        let mut e = EditSet::default();
        e.set_cell(1, 0, "30".into(), "3".into());
        e.set_cell(1, 1, "40".into(), "4".into());
        e.set_mark(0, 4, None);
        e.stamp(&src, "ab".into(), d, "first".into());
        let path = dir.join("versions").join("first.gsedit");
        e.save_for(&src, &path).unwrap();
        let back = EditSet::load(&path).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.name, "first");
        assert!(back.saved_at.is_some());
        // bound to the bytes and to the parser settings
        assert!(back.check(src.len(), Some("ab"), d).is_ok());
        assert!(back.check(src.len(), None, d).is_err(), "no digest yet");
        assert!(back.check(src.len() + 1, Some("ab"), d).is_err());
        assert!(back.check(src.len(), Some("cd"), d).is_err());
        let no_header = Dialect {
            has_header: false,
            ..d
        };
        assert!(
            back.check(src.len(), Some("ab"), no_header)
                .unwrap_err()
                .contains("parser settings")
        );
        let mut undigested = back.clone();
        undigested.source.sha256 = None;
        assert!(undigested.check(src.len(), Some("ab"), d).is_err());
        // never over the evidence
        assert!(e.save_for(&src, &src_path).is_err());
        assert_eq!(fs::read(&src_path).unwrap(), b"a,b\n1,2\n3,4\n");
        // the manifest record covers the cells written, named, the original
        // hashed, and no value for a redacted column
        let names = ["a".to_string(), "b".to_string()];
        let info = e.info_applied(&[(1, 0), (1, 1)], &names, &|c| c == 1);
        assert_eq!(info.version, "first");
        assert_eq!(info.marks, 1);
        assert_eq!(info.cells.len(), 2);
        assert_eq!(info.cells[0].name, "a");
        assert_eq!(info.cells[0].value.as_deref(), Some("30"));
        assert_eq!(info.cells[0].was_sha256, hex(&Sha256::digest(b"3")));
        assert_eq!(info.cells[1].value, None, "column b is redacted");
        let none = e.info_applied(&[], &names, &|_| false);
        assert!(none.cells.is_empty(), "nothing written, nothing listed");
        assert_eq!(e.cells_for(1).len(), 2);
        assert!(e.cells_for(0).is_empty());
        // other format versions are refused, including 0.1.0's
        for v in [1, 99] {
            fs::write(&path, format!(r#"{{"version":{v},"cells":[]}}"#)).unwrap();
            assert!(EditSet::load(&path).is_err());
        }
    }
}
