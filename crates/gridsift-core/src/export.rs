//! Export a selection of records to a new file, with digests, atomically.
//!
//! The source is never touched. Records are written as their exact source
//! bytes (quoting preserved) followed by a normalised terminator, so an
//! export is a byte-faithful subset of the evidence. The output is written to
//! a temporary file in the destination directory and renamed into place only
//! when complete, so an interrupted export leaves no half-written artefact.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::hash::{Digests, HashSelection, MultiHasher};
use crate::index::SparseIndex;
use crate::reader::{locate_many, stream_records};
use crate::scan::Control;
use crate::search::MatchSet;
use crate::source::Source;

/// Which records to export.
#[derive(Clone, Copy, Debug)]
pub enum Selection<'a> {
    All,
    Matches(&'a MatchSet),
    Range { first: u64, count: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminator {
    Lf,
    Crlf,
}

impl Terminator {
    pub fn bytes(&self) -> &'static [u8] {
        match self {
            Terminator::Lf => b"\n",
            Terminator::Crlf => b"\r\n",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExportOptions<'a> {
    pub include_header: bool,
    pub terminator: Terminator,
    pub hash: HashSelection,
    pub chunk_size: usize,
    /// Overwrite an existing output file.
    pub overwrite: bool,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for ExportOptions<'_> {
    fn default() -> Self {
        ExportOptions {
            include_header: true,
            terminator: Terminator::Lf,
            hash: HashSelection::SHA256,
            chunk_size: 8 << 20,
            overwrite: false,
            cancel: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExportReport {
    pub path: PathBuf,
    /// Data records written (header excluded).
    pub records: u64,
    pub bytes: u64,
    pub digests: Digests,
    pub elapsed: Duration,
    /// `false` if cancelled; no output file exists in that case.
    pub complete: bool,
}

/// Writer that hashes everything it writes.
struct Tee<W: Write> {
    inner: W,
    hasher: MultiHasher,
    bytes: u64,
}

impl<W: Write> Tee<W> {
    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data)?;
        self.hasher.update(data);
        self.bytes += data.len() as u64;
        Ok(())
    }
}

/// Run an export. `progress` receives `(records written, source bytes
/// consumed)` periodically.
pub fn export(
    source: &Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    opts: ExportOptions<'_>,
    out: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> io::Result<ExportReport> {
    let started = Instant::now();
    guard_output_path(source, out, opts.overwrite)?;
    let tmp = temp_path(out);
    let file = fs::File::create(&tmp)?;
    let mut w = Tee {
        inner: BufWriter::with_capacity(4 << 20, file),
        hasher: MultiHasher::new(opts.hash),
        bytes: 0,
    };
    let term = opts.terminator.bytes();
    let mut records = 0u64;

    let result = (|| -> io::Result<bool> {
        if opts.include_header {
            if let Some(h) = index.header {
                w.put(source.slice(h.start, h.end))?;
                w.put(term)?;
            }
        }
        match selection {
            Selection::All => {
                let Some(cp) = index.locate(0) else {
                    return Ok(true);
                };
                let mut err = None;
                let mut last_report = Instant::now();
                let ok = stream_records(
                    source,
                    index,
                    cp,
                    opts.chunk_size,
                    opts.cancel,
                    &mut |sp, bytes| {
                        if let Err(e) = w.put(bytes).and_then(|_| w.put(term)) {
                            err = Some(e);
                            return Control::Stop;
                        }
                        records += 1;
                        if last_report.elapsed() > Duration::from_millis(100) {
                            progress(records, sp.end);
                            last_report = Instant::now();
                        }
                        Control::Continue
                    },
                )?;
                match err {
                    Some(e) => Err(e),
                    None => Ok(ok),
                }
            }
            Selection::Range { first, count } => {
                let Some(cp) = index.locate(first) else {
                    return Ok(true);
                };
                let last = first.saturating_add(count);
                let mut err = None;
                let mut last_report = Instant::now();
                let ok = stream_records(
                    source,
                    index,
                    cp,
                    opts.chunk_size,
                    opts.cancel,
                    &mut |sp, bytes| {
                        if sp.ordinal >= last {
                            return Control::Stop;
                        }
                        if sp.ordinal >= first {
                            if let Err(e) = w.put(bytes).and_then(|_| w.put(term)) {
                                err = Some(e);
                                return Control::Stop;
                            }
                            records += 1;
                            if last_report.elapsed() > Duration::from_millis(100) {
                                progress(records, sp.end);
                                last_report = Instant::now();
                            }
                        }
                        Control::Continue
                    },
                )?;
                match err {
                    Some(e) => Err(e),
                    None => Ok(ok),
                }
            }
            Selection::Matches(m) => {
                // Jump straight to each match via the index; consecutive
                // matches under the same checkpoint share one scan.
                let mut it = m.iter();
                loop {
                    if opts.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return Ok(false);
                    }
                    let batch: Vec<u64> = it.by_ref().take(8192).collect();
                    if batch.is_empty() {
                        break;
                    }
                    let mut last_end = 0;
                    for r in locate_many(source, index, &batch) {
                        w.put(r.raw(source))?;
                        w.put(term)?;
                        records += 1;
                        last_end = r.end;
                    }
                    progress(records, last_end);
                }
                Ok(true)
            }
        }
    })();

    match result {
        Ok(true) => {
            w.inner.flush()?;
            let file = w.inner.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            if opts.overwrite && out.exists() {
                fs::remove_file(out)?;
            }
            fs::rename(&tmp, out)?;
            Ok(ExportReport {
                path: out.to_path_buf(),
                records,
                bytes: w.bytes,
                digests: w.hasher.finalize(),
                elapsed: started.elapsed(),
                complete: true,
            })
        }
        Ok(false) => {
            drop(w);
            let _ = fs::remove_file(&tmp);
            Ok(ExportReport {
                path: out.to_path_buf(),
                records,
                bytes: 0,
                digests: Digests::default(),
                elapsed: started.elapsed(),
                complete: false,
            })
        }
        Err(e) => {
            drop(w);
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Refuse to write onto the evidence itself, or over an existing file
/// unless asked to.
fn guard_output_path(source: &Source, out: &Path, overwrite: bool) -> io::Result<()> {
    if let (Ok(a), Ok(b)) = (fs::canonicalize(source.path()), fs::canonicalize(out)) {
        if a == b {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to overwrite the source file",
            ));
        }
    }
    if out.exists() && !overwrite {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", out.display()),
        ));
    }
    if out.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a directory", out.display()),
        ));
    }
    Ok(())
}

fn temp_path(out: &Path) -> PathBuf {
    let name = out
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".into());
    out.with_file_name(format!(".{name}.gridsift-tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{BuildOptions, IndexParams, build_index};
    use crate::search::{SearchOptions, SearchQuery, SearchShared, search};
    use std::sync::atomic::AtomicUsize;

    fn workdir() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gridsift-export-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture(dir: &Path, data: &[u8], stride: u32) -> (Source, SparseIndex) {
        let p = dir.join("source.csv");
        fs::write(&p, data).unwrap();
        let src = Source::open(&p).unwrap();
        let params = IndexParams {
            stride_records: stride,
            stride_bytes: u64::MAX,
            ..IndexParams::default()
        };
        let idx = build_index(&src, params, BuildOptions::default(), &mut |_, _| {}).unwrap();
        (src, idx)
    }

    fn sha(path: &Path) -> Digests {
        let s = Source::open(path).unwrap();
        crate::hash::hash_source(&s, HashSelection::SHA256, 1 << 20, None)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn export_all_is_byte_faithful() {
        let dir = workdir();
        let data = b"id,text\r\n1,\"a,b\"\r\n\r\n2,\"line\nbreak\"\r\n3,x";
        let (src, idx) = fixture(&dir, data, 1);
        let out = dir.join("all.csv");
        let rep = export(
            &src,
            &idx,
            Selection::All,
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        assert!(rep.complete);
        assert_eq!(rep.records, 3);
        let got = fs::read(&out).unwrap();
        // exact record bytes, normalised LF terminators, blank line dropped, final newline added
        assert_eq!(got, b"id,text\n1,\"a,b\"\n2,\"line\nbreak\"\n3,x\n");
        assert_eq!(rep.bytes as usize, got.len());
        assert_eq!(rep.digests, sha(&out));
        // temp file is gone
        assert!(fs::read_dir(&dir).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .contains("gridsift-tmp")
        }));
        // CRLF + no header
        let out2 = dir.join("crlf.csv");
        let opts = ExportOptions {
            include_header: false,
            terminator: Terminator::Crlf,
            ..ExportOptions::default()
        };
        export(&src, &idx, Selection::All, opts, &out2, &mut |_, _| {}).unwrap();
        assert_eq!(
            fs::read(&out2).unwrap(),
            b"1,\"a,b\"\r\n2,\"line\nbreak\"\r\n3,x\r\n"
        );
    }

    #[test]
    fn export_matches_and_range() {
        let dir = workdir();
        let mut data = b"id,host\n".to_vec();
        for i in 0..5000 {
            data.extend_from_slice(
                format!(
                    "{i},{}\n",
                    if i % 7 == 0 {
                        "evil.example"
                    } else {
                        "ok.example"
                    }
                )
                .as_bytes(),
            );
        }
        let (src, idx) = fixture(&dir, &data, 64);
        let q = SearchQuery::literal("evil");
        let c = q.compile(idx.params.dialect).unwrap();
        let shared = SearchShared::new(src.len());
        search(&src, &idx, &c, SearchOptions::default(), &shared);
        let m = shared.matches.lock().unwrap();
        assert_eq!(m.len(), 715);
        let out = dir.join("matches.csv");
        let rep = export(
            &src,
            &idx,
            Selection::Matches(&m),
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(rep.records, 715);
        let text = fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "id,host");
        assert_eq!(lines.len(), 716);
        assert!(lines[1..].iter().all(|l| l.ends_with(",evil.example")));
        assert_eq!(lines[1], "0,evil.example");
        assert_eq!(lines[715], "4998,evil.example");
        assert_eq!(rep.digests, sha(&out));

        let out = dir.join("range.csv");
        let rep = export(
            &src,
            &idx,
            Selection::Range {
                first: 4990,
                count: 100,
            },
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(rep.records, 10);
        let text = fs::read_to_string(&out).unwrap();
        assert!(text.starts_with("id,host\n4990,"));
        assert!(text.ends_with("4999,ok.example\n"));
    }

    #[test]
    fn guards_and_cancel() {
        let dir = workdir();
        let (src, idx) = fixture(&dir, b"a,b\n1,2\n", 1);
        // never onto the source
        let e = export(
            &src,
            &idx,
            Selection::All,
            ExportOptions::default(),
            src.path(),
            &mut |_, _| {},
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // no silent overwrite
        let out = dir.join("out.csv");
        export(
            &src,
            &idx,
            Selection::All,
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        let e = export(
            &src,
            &idx,
            Selection::All,
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        let opts = ExportOptions {
            overwrite: true,
            ..ExportOptions::default()
        };
        export(&src, &idx, Selection::All, opts, &out, &mut |_, _| {}).unwrap();
        // cancel leaves nothing behind
        let cancel = AtomicBool::new(true);
        let opts = ExportOptions {
            cancel: Some(&cancel),
            ..ExportOptions::default()
        };
        let out2 = dir.join("cancelled.csv");
        let rep = export(&src, &idx, Selection::All, opts, &out2, &mut |_, _| {}).unwrap();
        assert!(!rep.complete);
        assert!(!out2.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2); // source + out.csv
    }
}
