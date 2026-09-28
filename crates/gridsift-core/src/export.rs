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

use crate::dialect::Dialect;
use crate::enrich::Enrichment;
use crate::hash::{Digests, HashSelection, MultiHasher};
use crate::index::SparseIndex;
use crate::reader::{locate_many, stream_records};
use crate::record::write_field;
use crate::redact::Redactor;
use crate::scan::Control;
use crate::search::MatchSet;
use crate::source::Source;

/// Which records an operation (export, frequency count, …) applies to.
#[derive(Clone, Copy, Debug)]
pub enum Selection<'a> {
    All,
    Matches(&'a MatchSet),
    Range { first: u64, count: u64 },
}

impl Selection<'_> {
    #[inline]
    pub fn includes(&self, ordinal: u64) -> bool {
        match self {
            Selection::All => true,
            Selection::Matches(m) => m.contains(ordinal),
            Selection::Range { first, count } => {
                ordinal >= *first && ordinal < first.saturating_add(*count)
            }
        }
    }

    /// Number of records selected, when known without scanning.
    pub fn size_hint(&self, total: u64) -> u64 {
        match self {
            Selection::All => total,
            Selection::Matches(m) => m.len(),
            Selection::Range { first, count } => (*count).min(total.saturating_sub(*first)),
        }
    }
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
    /// Column redaction to apply to every written record (and the header).
    pub redactor: Option<&'a Redactor>,
    /// Derived columns to append to every written record (and the header).
    pub enrichment: Option<&'a Enrichment>,
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
            redactor: None,
            enrichment: None,
            cancel: None,
        }
    }
}

/// Per-record output transform: redaction of source columns, then derived
/// columns appended from enrichment (computed from the original values, so
/// a pseudonymised IP still yields its real country).
struct Transform<'a> {
    redactor: Option<&'a Redactor>,
    enrichment: Option<&'a Enrichment>,
    dialect: Dialect,
    buf: Vec<u8>,
    derived: Vec<Vec<u8>>,
}

impl<'a> Transform<'a> {
    fn new(
        redactor: Option<&'a Redactor>,
        enrichment: Option<&'a Enrichment>,
        dialect: Dialect,
    ) -> Transform<'a> {
        Transform {
            redactor,
            enrichment,
            dialect,
            buf: Vec::new(),
            derived: Vec::new(),
        }
    }

    fn is_identity(&self) -> bool {
        self.redactor.is_none() && self.enrichment.is_none()
    }

    /// Render a data record into `self.buf`. Returns `false` when the record
    /// passes through untouched (the caller then writes `bytes` itself).
    fn record(&mut self, bytes: &[u8]) -> bool {
        if self.is_identity() {
            return false;
        }
        self.buf.clear();
        match self.redactor {
            Some(r) => r.render(bytes, &mut self.buf),
            None => self.buf.extend_from_slice(bytes),
        }
        if let Some(e) = self.enrichment {
            e.compute(bytes, &mut self.derived);
            for v in &self.derived {
                self.buf.push(self.dialect.delimiter);
                write_field(v, self.dialect.delimiter, self.dialect.quote, &mut self.buf);
            }
        }
        true
    }

    /// Same for the header record: dropped columns vanish, derived names
    /// are appended.
    fn header(&mut self, bytes: &[u8]) -> bool {
        if self.is_identity() {
            return false;
        }
        self.buf.clear();
        match self.redactor {
            Some(r) => r.render_header(bytes, &mut self.buf),
            None => self.buf.extend_from_slice(bytes),
        }
        if let Some(e) = self.enrichment {
            for name in e.derived_names() {
                self.buf.push(self.dialect.delimiter);
                write_field(
                    name.as_bytes(),
                    self.dialect.delimiter,
                    self.dialect.quote,
                    &mut self.buf,
                );
            }
        }
        true
    }
}

/// Write one record (transformed if asked) plus the terminator.
fn emit<W: Write>(
    w: &mut Tee<W>,
    tf: &mut Transform<'_>,
    bytes: &[u8],
    term: &[u8],
) -> io::Result<()> {
    if tf.record(bytes) {
        w.put(&tf.buf)?;
    } else {
        w.put(bytes)?;
    }
    w.put(term)
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
    /// The manifest written next to the output, if one was committed.
    pub manifest: Option<PathBuf>,
}

/// A finished export that has not been published yet: the records sit in a
/// temporary file next to the destination. [`PendingExport::commit`] writes
/// the manifest (if any) and renames the output into place; dropping the
/// value discards the temporary file.
///
/// Splitting the export in two lets the caller build the manifest from the
/// output's digest *before* anything visible exists, so the destination
/// never holds an output without its provenance.
#[must_use = "commit() or abort() the export"]
pub struct PendingExport<'s> {
    source: &'s Source,
    tmp: PathBuf,
    out: PathBuf,
    report: ExportReport,
    done: bool,
}

impl PendingExport<'_> {
    pub fn report(&self) -> &ExportReport {
        &self.report
    }

    /// Publish: manifest (staged and renamed) first, then the output. Both
    /// renames replace atomically, so an interrupted overwrite leaves the
    /// previous artefact of that name, never a truncated one. The one
    /// window that remains — a crash between the two renames — leaves a
    /// manifest whose recorded digest `verify` will flag against the older
    /// output.
    pub fn commit(
        mut self,
        manifest: Option<&crate::manifest::Manifest>,
    ) -> io::Result<ExportReport> {
        self.done = true;
        if !self.report.complete {
            let _ = fs::remove_file(&self.tmp);
            return Ok(self.report.clone());
        }
        let fail = |tmp: &Path, e: io::Error| {
            let _ = fs::remove_file(tmp);
            Err(e)
        };
        // the evidence must still be what the digest in the manifest says
        if let Err(e) = self.source.ensure_unchanged() {
            return fail(&self.tmp, e);
        }
        let mut mpath = None;
        if let Some(m) = manifest {
            let p = crate::manifest::Manifest::path_for(&self.out);
            if let Err(e) = m.write_for(self.source, &p) {
                return fail(&self.tmp, e);
            }
            mpath = Some(p);
        }
        if let Err(e) = fs::rename(&self.tmp, &self.out) {
            // do not leave a manifest that claims an output which never appeared
            if let Some(p) = &mpath {
                let _ = fs::remove_file(p);
            }
            return fail(&self.tmp, e);
        }
        self.report.manifest = mpath;
        Ok(self.report.clone())
    }

    /// Discard the temporary output.
    pub fn abort(mut self) {
        self.done = true;
        let _ = fs::remove_file(&self.tmp);
    }
}

impl Drop for PendingExport<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp);
        }
    }
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

/// Run an export and publish it without a manifest. `progress` receives
/// `(records written, source bytes consumed)` periodically.
pub fn export(
    source: &Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    opts: ExportOptions<'_>,
    out: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> io::Result<ExportReport> {
    export_pending(source, index, selection, opts, out, progress)?.commit(None)
}

/// Run an export into a temporary file and hand back the digest without
/// publishing anything; see [`PendingExport`]. The output plan (the
/// destination and its temporary) is checked against the evidence, and
/// the source must be unchanged since it was opened, before any byte is
/// written.
pub fn export_pending<'s>(
    source: &'s Source,
    index: &SparseIndex,
    selection: Selection<'_>,
    opts: ExportOptions<'_>,
    out: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> io::Result<PendingExport<'s>> {
    let started = Instant::now();
    guard_output_path(source, out, opts.overwrite)?;
    let tmp = temp_path(out);
    source.guard_not_source(&tmp)?;
    source.ensure_unchanged()?;
    let file = fs::File::create(&tmp)?;
    let mut w = Tee {
        inner: BufWriter::with_capacity(4 << 20, file),
        hasher: MultiHasher::new(opts.hash),
        bytes: 0,
    };
    let term = opts.terminator.bytes();
    let mut records = 0u64;
    let mut tf = Transform::new(opts.redactor, opts.enrichment, index.params.dialect);

    let result = (|| -> io::Result<bool> {
        if opts.include_header
            && let Some(h) = index.header
        {
            let raw = source.slice(h.start, h.end);
            if tf.header(raw) {
                w.put(&tf.buf)?;
            } else {
                w.put(raw)?;
            }
            w.put(term)?;
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
                        if let Err(e) = emit(&mut w, &mut tf, bytes, term) {
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
                            if let Err(e) = emit(&mut w, &mut tf, bytes, term) {
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
                        emit(&mut w, &mut tf, r.raw(source), term)?;
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
            if let Err(e) = w.inner.flush() {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
            let Tee {
                inner,
                hasher,
                bytes,
            } = w;
            let file = match inner.into_inner() {
                Ok(f) => f,
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(e.into_error());
                }
            };
            if let Err(e) = file.sync_all() {
                drop(file);
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
            drop(file);
            Ok(PendingExport {
                source,
                tmp,
                out: out.to_path_buf(),
                report: ExportReport {
                    path: out.to_path_buf(),
                    records,
                    bytes,
                    digests: hasher.finalize(),
                    elapsed: started.elapsed(),
                    complete: true,
                    manifest: None,
                },
                done: false,
            })
        }
        Ok(false) => {
            drop(w);
            let _ = fs::remove_file(&tmp);
            Ok(PendingExport {
                source,
                tmp,
                out: out.to_path_buf(),
                report: ExportReport {
                    path: out.to_path_buf(),
                    records,
                    bytes: 0,
                    digests: Digests::default(),
                    elapsed: started.elapsed(),
                    complete: false,
                    manifest: None,
                },
                done: false,
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
    source.guard_not_source(out)?;
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
    use crate::hash::hex;
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
    fn transforms_apply_in_order() {
        use crate::enrich::{EnrichRule, Enrichment, Provider};
        use crate::redact::{RedactMethod, RedactRule, Redactor};
        let dir = workdir();
        let data = b"ts,ip,host\n1,10.0.0.1,www.example.co.uk\n2,10.0.0.2,\"a,b.test.org\"\n";
        let (src, idx) = fixture(&dir, data, 1);
        let dialect = idx.params.dialect;
        let enrichment = Enrichment::new(
            dialect,
            vec![EnrichRule {
                column: 2,
                name: "host".into(),
                provider: Provider::Domain,
            }],
        );
        let redactor = Redactor::new(
            dialect,
            vec![RedactRule {
                column: 1,
                name: "ip".into(),
                method: RedactMethod::Mask {
                    replacement: "x".into(),
                },
            }],
            None,
        )
        .unwrap();
        let out = dir.join("tf.csv");
        let opts = ExportOptions {
            redactor: Some(&redactor),
            enrichment: Some(&enrichment),
            ..ExportOptions::default()
        };
        export(&src, &idx, Selection::All, opts, &out, &mut |_, _| {}).unwrap();
        let text = fs::read_to_string(&out).unwrap();
        assert_eq!(
            text,
            "ts,ip,host,host.registrable,host.suffix,host.subdomain\n\
             1,x,www.example.co.uk,example.co.uk,co.uk,www\n\
             2,x,\"a,b.test.org\",test.org,org,\"a,b\"\n"
        );
        // enrichment alone leaves source bytes untouched
        let out2 = dir.join("tf2.csv");
        let opts = ExportOptions {
            enrichment: Some(&enrichment),
            ..ExportOptions::default()
        };
        export(
            &src,
            &idx,
            Selection::Range { first: 0, count: 1 },
            opts,
            &out2,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(&out2).unwrap(),
            "ts,ip,host,host.registrable,host.suffix,host.subdomain\n1,10.0.0.1,www.example.co.uk,example.co.uk,co.uk,www\n"
        );
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

    #[test]
    fn output_plan_never_touches_the_evidence() {
        let dir = workdir();
        let (src, idx) = fixture(&dir, b"a,b\n1,2\n", 1);
        let before = fs::read(src.path()).unwrap();
        // a hard link or copy with the source's identity is refused too
        let twin = dir.join("twin.csv");
        fs::hard_link(src.path(), &twin).unwrap();
        for target in [src.path().to_path_buf(), twin.clone()] {
            let e = export(
                &src,
                &idx,
                Selection::All,
                ExportOptions {
                    overwrite: true,
                    ..ExportOptions::default()
                },
                &target,
                &mut |_, _| {},
            )
            .unwrap_err();
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidInput,
                "{}",
                target.display()
            );
            assert!(src.guard_not_source(&target).is_err());
        }
        assert_eq!(fs::read(src.path()).unwrap(), before);
        // the manifest path and index sidecar go through the same check
        let m = crate::manifest::Manifest::new(
            crate::manifest::SourceInfo::from_source(&src, idx.params.dialect, idx.digests, None),
            vec![],
            crate::manifest::SelectionInfo::All,
            crate::manifest::OutputInfo {
                path: String::new(),
                name: String::new(),
                format: "csv".into(),
                content: "raw-records".into(),
                header: true,
                terminator: "\n".into(),
                records: 0,
                size: 0,
                sha256: None,
                blake3: None,
            },
        );
        assert!(m.write_for(&src, src.path()).is_err());
        assert!(idx.save_for(&src, src.path()).is_err());
        assert!(idx.save_for(&src, &twin).is_err());
        assert_eq!(fs::read(src.path()).unwrap(), before);
    }

    #[test]
    fn commit_publishes_manifest_then_output_and_detects_a_changed_source() {
        let dir = workdir();
        let (src, idx) = fixture(&dir, b"a,b\n1,2\n3,4\n", 1);
        let out = dir.join("out.csv");
        let pending = export_pending(
            &src,
            &idx,
            Selection::All,
            ExportOptions::default(),
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        // nothing visible before commit
        assert!(!out.exists());
        let digest = hex(&pending.report().digests.sha256.unwrap());
        let m = crate::manifest::Manifest::new(
            crate::manifest::SourceInfo::from_source(&src, idx.params.dialect, idx.digests, None),
            vec![],
            crate::manifest::SelectionInfo::All,
            crate::manifest::OutputInfo {
                path: out.display().to_string(),
                name: "out.csv".into(),
                format: "csv".into(),
                content: "raw-records".into(),
                header: true,
                terminator: "\n".into(),
                records: pending.report().records,
                size: pending.report().bytes,
                sha256: Some(digest.clone()),
                blake3: None,
            },
        );
        let rep = pending.commit(Some(&m)).unwrap();
        let mpath = crate::manifest::Manifest::path_for(&out);
        assert_eq!(rep.manifest.as_deref(), Some(mpath.as_path()));
        assert!(out.exists() && mpath.exists());
        assert_eq!(
            crate::manifest::Manifest::read(&mpath)
                .unwrap()
                .output
                .sha256,
            Some(digest)
        );
        // no temporaries left behind
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);

        // an aborted pending export leaves the previous artefacts alone
        let pending = export_pending(
            &src,
            &idx,
            Selection::Range { first: 0, count: 1 },
            ExportOptions {
                overwrite: true,
                ..ExportOptions::default()
            },
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        pending.abort();
        assert_eq!(rep.bytes, fs::metadata(&out).unwrap().len());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);

        // the evidence changes under us: neither a new export nor a commit
        // may go through with the old digest
        let pending = export_pending(
            &src,
            &idx,
            Selection::All,
            ExportOptions {
                overwrite: true,
                ..ExportOptions::default()
            },
            &out,
            &mut |_, _| {},
        )
        .unwrap();
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(src.path())
            .unwrap();
        f.write_all(b"5,6\n").unwrap();
        drop(f);
        assert!(pending.commit(None).is_err());
        assert!(
            export_pending(
                &src,
                &idx,
                Selection::All,
                ExportOptions::default(),
                &dir.join("later.csv"),
                &mut |_, _| {},
            )
            .is_err()
        );
        assert_eq!(rep.bytes, fs::metadata(&out).unwrap().len());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
    }
}
