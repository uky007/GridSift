//! Quote-aware structural scanner.
//!
//! Finds logical CSV record boundaries in a byte stream without materialising
//! fields. The scanner is resumable across arbitrary chunk boundaries, so the
//! same code drives the sequential pass over a 100 GB file and the short
//! forward scans from a checkpoint to a viewport.
//!
//! Quoting rules match the `csv` crate's lenient defaults (verified by the
//! differential tests in `tests/differential.rs`):
//!
//! - a quote opens a quoted field only at the start of a field
//! - inside a quoted field `""` is an escaped quote; any other byte after a
//!   quote closes the field and the rest up to the delimiter is literal
//! - a quote anywhere else is a literal byte
//! - `\n`, `\r` and `\r\n` all terminate a record; empty lines are skipped
//! - a final record without a terminator is still a record
//!
//! Only quote and terminator bytes are inspected byte-by-byte; everything in
//! between is skipped with `memchr`, so throughput is bounded by memory
//! bandwidth rather than per-byte state transitions.

use memchr::{memchr, memchr2, memchr3};

/// Byte-level dialect parameters the scanner needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanConfig {
    pub delimiter: u8,
    /// `None` disables quote handling entirely, e.g. for raw TSV logs that
    /// contain unbalanced quotes.
    pub quote: Option<u8>,
    /// Count delimiters per record so the sink receives a field count. Costs an
    /// extra SIMD pass over unquoted bytes; disable for pure boundary scans.
    pub count_fields: bool,
}

/// One logical record located by the scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordSpan {
    /// 0-based ordinal of the record, counted from the scanner's starting ordinal.
    pub ordinal: u64,
    /// Absolute byte offset of the first byte of the record.
    pub start: u64,
    /// Absolute byte offset one past the last content byte. The terminator is
    /// excluded, so `start..end` is exactly the record's content.
    pub end: u64,
    /// `1 + unquoted delimiters` when `count_fields` is on, otherwise 0.
    pub fields: u32,
    /// The record ran into EOF inside an open quoted field.
    pub unterminated_quote: bool,
    /// A closing quote was followed by literal bytes instead of a delimiter or
    /// terminator (`"abc"def`). Accepted leniently, but a strong hint that the
    /// producer did not quote properly.
    pub lenient_quote: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    Stop,
}

/// Receiver of record spans. Closures `FnMut(RecordSpan) -> Control` implement it.
pub trait Sink {
    fn record(&mut self, span: RecordSpan) -> Control;
}

impl<F: FnMut(RecordSpan) -> Control> Sink for F {
    #[inline]
    fn record(&mut self, span: RecordSpan) -> Control {
        self(span)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Between records; nothing of the next record consumed yet.
    RecordStart,
    /// Saw a `\r` that ended a record; a following `\n` belongs to it.
    AfterCr,
    /// Inside a record, outside quotes. `field_start` is true iff a quote at
    /// the current position opens a quoted field.
    Unquoted { field_start: bool },
    /// Inside a quoted field.
    Quoted,
    /// Saw a quote inside a quoted field; the next byte decides escape vs close.
    QuoteInQuoted,
}

/// Resumable record-boundary scanner. Feed contiguous chunks with [`Scanner::feed`]
/// and call [`Scanner::finish`] at EOF.
#[derive(Clone, Debug)]
pub struct Scanner {
    cfg: ScanConfig,
    state: State,
    /// Absolute offset of the start of the record being scanned.
    rec_start: u64,
    /// Unquoted delimiters seen in the current record (saturating).
    delims: u32,
    /// The current record had a lenient quote closure.
    lenient: bool,
    ordinal: u64,
    /// Absolute offset of the next byte to be fed.
    pos: u64,
}

impl Scanner {
    /// Scanner positioned at offset 0, record ordinal 0.
    pub fn new(cfg: ScanConfig) -> Self {
        Self::at(cfg, 0, 0)
    }

    /// Scanner resuming at a known record boundary: `offset` must be the first
    /// byte of a record (or EOF), which will be reported as `ordinal`.
    pub fn at(cfg: ScanConfig, offset: u64, ordinal: u64) -> Self {
        Scanner {
            cfg,
            state: State::RecordStart,
            rec_start: offset,
            delims: 0,
            lenient: false,
            ordinal,
            pos: offset,
        }
    }

    pub fn config(&self) -> ScanConfig {
        self.cfg
    }

    /// Absolute offset of the next byte the scanner expects.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Ordinal the next emitted record will carry.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Feed the next contiguous chunk. Returns [`Control::Stop`] as soon as the
    /// sink asks to stop; the scanner then sits just past the terminator of the
    /// record it reported and [`Scanner::pos`] tells how much of `chunk` was
    /// consumed, so feeding can resume from there.
    pub fn feed<S: Sink>(&mut self, chunk: &[u8], sink: &mut S) -> Control {
        let base = self.pos;
        let n = chunk.len();
        let delim = self.cfg.delimiter;
        let mut i = 0usize;

        while i < n {
            match self.state {
                State::AfterCr => {
                    self.state = State::RecordStart;
                    if chunk[i] == b'\n' {
                        i += 1;
                    }
                }
                State::RecordStart => match chunk[i] {
                    b'\n' => i += 1,
                    b'\r' => {
                        self.state = State::AfterCr;
                        i += 1;
                    }
                    _ => {
                        self.rec_start = base + i as u64;
                        self.delims = 0;
                        self.lenient = false;
                        self.state = State::Unquoted { field_start: true };
                    }
                },
                State::Unquoted { field_start } => {
                    let run_start = i;
                    let rest = &chunk[i..];
                    let hit = match self.cfg.quote {
                        Some(q) => memchr3(q, b'\n', b'\r', rest),
                        None => memchr2(b'\n', b'\r', rest),
                    };
                    let end = i + hit.unwrap_or(rest.len());
                    if self.cfg.count_fields && end > run_start {
                        let c = bytecount::count(&chunk[run_start..end], delim);
                        self.delims = self.delims.saturating_add(c.min(u32::MAX as usize) as u32);
                    }
                    if hit.is_none() {
                        // Chunk exhausted inside a record: remember whether the
                        // next byte would sit at a field start.
                        if end > run_start {
                            self.state = State::Unquoted {
                                field_start: chunk[end - 1] == delim,
                            };
                        }
                        break;
                    }
                    let b = chunk[end];
                    i = end + 1;
                    if b == b'\n' || b == b'\r' {
                        self.state = if b == b'\r' {
                            State::AfterCr
                        } else {
                            State::RecordStart
                        };
                        if self.emit(sink, base + end as u64, false) == Control::Stop {
                            self.pos = base + i as u64;
                            return Control::Stop;
                        }
                    } else {
                        // A quote opens a quoted field only at a field start.
                        let opens = if end == run_start {
                            field_start
                        } else {
                            chunk[end - 1] == delim
                        };
                        self.state = if opens {
                            State::Quoted
                        } else {
                            State::Unquoted { field_start: false }
                        };
                    }
                }
                State::Quoted => {
                    let q = self.cfg.quote.expect("Quoted state requires a quote byte");
                    match memchr(q, &chunk[i..]) {
                        Some(p) => {
                            self.state = State::QuoteInQuoted;
                            i += p + 1;
                        }
                        None => i = n,
                    }
                }
                State::QuoteInQuoted => {
                    let b = chunk[i];
                    if Some(b) == self.cfg.quote {
                        // `""` inside a quoted field: escaped quote.
                        self.state = State::Quoted;
                        i += 1;
                    } else {
                        // Closing quote; the byte is re-examined as unquoted content.
                        if b != delim && b != b'\n' && b != b'\r' {
                            self.lenient = true;
                        }
                        self.state = State::Unquoted { field_start: false };
                    }
                }
            }
        }

        self.pos = base + n as u64;
        Control::Continue
    }

    /// Signal EOF. Emits the final record if the input did not end with a
    /// terminator. The scanner is left at a record boundary.
    pub fn finish<S: Sink>(&mut self, sink: &mut S) -> Control {
        let ctl = match self.state {
            State::RecordStart | State::AfterCr => Control::Continue,
            State::Unquoted { .. } | State::QuoteInQuoted => self.emit(sink, self.pos, false),
            State::Quoted => self.emit(sink, self.pos, true),
        };
        self.state = State::RecordStart;
        ctl
    }

    #[inline]
    fn emit<S: Sink>(&mut self, sink: &mut S, end: u64, unterminated_quote: bool) -> Control {
        let span = RecordSpan {
            ordinal: self.ordinal,
            start: self.rec_start,
            end,
            fields: if self.cfg.count_fields {
                self.delims.saturating_add(1)
            } else {
                0
            },
            unterminated_quote,
            lenient_quote: self.lenient,
        };
        self.ordinal += 1;
        sink.record(span)
    }
}

/// Scan a complete in-memory buffer and collect every record span.
/// Convenience for tests and small inputs.
pub fn scan_all(cfg: ScanConfig, data: &[u8]) -> Vec<RecordSpan> {
    let mut out = Vec::new();
    let mut scanner = Scanner::new(cfg);
    let mut sink = |s: RecordSpan| {
        out.push(s);
        Control::Continue
    };
    scanner.feed(data, &mut sink);
    scanner.finish(&mut sink);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: ScanConfig = ScanConfig {
        delimiter: b',',
        quote: Some(b'"'),
        count_fields: true,
    };

    fn spans(data: &[u8]) -> Vec<(u64, u64, u32)> {
        scan_all(CFG, data)
            .into_iter()
            .map(|s| (s.start, s.end, s.fields))
            .collect()
    }

    #[test]
    fn plain_records_all_terminators() {
        assert_eq!(spans(b"a,b\nc,d\n"), vec![(0, 3, 2), (4, 7, 2)]);
        assert_eq!(spans(b"a,b\r\nc,d\r\n"), vec![(0, 3, 2), (5, 8, 2)]);
        assert_eq!(spans(b"a,b\rc,d\r"), vec![(0, 3, 2), (4, 7, 2)]);
        assert_eq!(spans(b"a,b\nc,d"), vec![(0, 3, 2), (4, 7, 2)]);
        assert_eq!(spans(b"a,b\r\nc,d\n"), vec![(0, 3, 2), (5, 8, 2)]);
    }

    #[test]
    fn empty_lines_are_skipped() {
        assert_eq!(spans(b""), vec![]);
        assert_eq!(spans(b"\n\n\r\n"), vec![]);
        assert_eq!(spans(b"\n\na\n\n\nb\n\n"), vec![(2, 3, 1), (6, 7, 1)]);
        assert_eq!(spans(b"\r\r\na\r\r"), vec![(3, 4, 1)]);
    }

    #[test]
    fn quoted_newlines_and_escapes() {
        // newline inside quotes does not terminate the record
        assert_eq!(spans(b"a,\"x\ny\"\nb\n"), vec![(0, 7, 2), (8, 9, 1)]);
        assert_eq!(spans(b"a,\"x\r\ny\"\r\nb"), vec![(0, 8, 2), (10, 11, 1)]);
        // escaped quote inside quotes
        assert_eq!(spans(b"\"a\"\"b\",c\n"), vec![(0, 8, 2)]);
        // delimiter inside quotes is not counted
        assert_eq!(spans(b"\"a,b\",c\n"), vec![(0, 7, 2)]);
        // quoted empty field
        assert_eq!(spans(b"\"\",\"\"\n"), vec![(0, 5, 2)]);
        // lenient: bytes after the closing quote are literal
        assert_eq!(spans(b"\"a\"b,c\n"), vec![(0, 6, 2)]);
        assert_eq!(spans(b"\"a\"b\nc\n"), vec![(0, 4, 1), (5, 6, 1)]);
    }

    #[test]
    fn lenient_closures_are_flagged() {
        let s = scan_all(CFG, b"\"a\"b,c\n\"d\",e\n\"f\"\n\"g\"");
        let flags: Vec<bool> = s.iter().map(|s| s.lenient_quote).collect();
        assert_eq!(flags, vec![true, false, false, false]);
        // a quote that never opened a field is literal, not lenient
        let s = scan_all(CFG, b"a\"b\"c,d\n");
        assert!(!s[0].lenient_quote);
    }

    #[test]
    fn quote_mid_field_is_literal() {
        assert_eq!(spans(b"a\"b,c\n"), vec![(0, 5, 2)]);
        // a literal quote does not open quoting, so this newline terminates
        assert_eq!(spans(b"a\"b\nc\"\n"), vec![(0, 3, 1), (4, 6, 1)]);
    }

    #[test]
    fn unterminated_quote_is_flagged() {
        let s = scan_all(CFG, b"a,\"open\nstill");
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].start, s[0].end), (0, 13));
        assert!(s[0].unterminated_quote);
        // closing quote right at EOF is fine
        let s = scan_all(CFG, b"a,\"x\"");
        assert!(!s[0].unterminated_quote);
        assert_eq!(s[0].fields, 2);
    }

    #[test]
    fn no_quote_mode() {
        let cfg = ScanConfig { quote: None, ..CFG };
        let s = scan_all(cfg, b"\"a\nb\",c\n");
        assert_eq!(
            s.iter()
                .map(|s| (s.start, s.end, s.fields))
                .collect::<Vec<_>>(),
            vec![(0, 2, 1), (3, 7, 2)]
        );
    }

    #[test]
    fn ordinals_and_resume() {
        let s = scan_all(CFG, b"a\nb\nc\n");
        assert_eq!(
            s.iter().map(|s| s.ordinal).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let mut sc = Scanner::at(CFG, 4, 2);
        let mut got = Vec::new();
        sc.feed(b"c\nd\n", &mut |s: RecordSpan| {
            got.push(s);
            Control::Continue
        });
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].ordinal, got[0].start, got[0].end), (2, 4, 5));
        assert_eq!((got[1].ordinal, got[1].start, got[1].end), (3, 6, 7));
    }

    #[test]
    fn stop_leaves_scanner_resumable() {
        let data = b"a\nb\nc\n";
        let mut sc = Scanner::new(CFG);
        let mut n = 0;
        let ctl = sc.feed(data, &mut |_s: RecordSpan| {
            n += 1;
            if n == 2 {
                Control::Stop
            } else {
                Control::Continue
            }
        });
        assert_eq!(ctl, Control::Stop);
        assert_eq!(sc.pos(), 4);
        let mut rest = Vec::new();
        sc.feed(&data[sc.pos() as usize..], &mut |s: RecordSpan| {
            rest.push(s);
            Control::Continue
        });
        sc.finish(&mut |_s: RecordSpan| Control::Continue);
        assert_eq!(rest.len(), 1);
        assert_eq!((rest[0].ordinal, rest[0].start, rest[0].end), (2, 4, 5));
    }

    /// The crucial property: feeding in chunks of any size yields exactly the
    /// same spans as feeding the whole buffer at once.
    #[test]
    fn chunk_boundary_invariance() {
        let corpus: &[&[u8]] = &[
            b"a,b\nc,d\n",
            b"a,b\r\nc,d\r\n",
            b"\r\n\r\na\r\r\nb",
            b"a,\"x\r\ny\"\r\nb,\"\"\"\"\n",
            b"\"a\"\"b\",\"c,d\"\n\"e\"f,g\r\n",
            b"x,\"unterminated\nstill",
            b"\"\",\"\",\n,,\n\"a\"\"\"\n",
            b"1,\"2\",3\r\n\"4\r\",5\n\n\n6",
        ];
        for data in corpus {
            let expect = scan_all(CFG, data);
            for chunk in 1..=data.len() {
                let mut sc = Scanner::new(CFG);
                let mut got = Vec::new();
                let mut sink = |s: RecordSpan| {
                    got.push(s);
                    Control::Continue
                };
                for piece in data.chunks(chunk) {
                    sc.feed(piece, &mut sink);
                }
                sc.finish(&mut sink);
                assert_eq!(got, expect, "chunk size {chunk} on {:?}", data);
            }
        }
    }
}
