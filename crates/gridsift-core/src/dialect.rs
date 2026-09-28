//! Dialect detection from the head of a file.
//!
//! Sniffing is an inference over a sample, never a silent decision: the result
//! carries the evidence it was based on so a UI can show it and let the analyst
//! override any part.

use std::borrow::Cow;

use crate::record::split_fields;
use crate::scan::{Control, RecordSpan, ScanConfig, Scanner};

/// Byte-level CSV dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dialect {
    pub delimiter: u8,
    /// `None` disables quoting entirely.
    pub quote: Option<u8>,
    /// The first record is a header, not data.
    pub has_header: bool,
}

impl Dialect {
    pub fn scan_config(&self, count_fields: bool) -> ScanConfig {
        ScanConfig {
            delimiter: self.delimiter,
            quote: self.quote,
            count_fields,
        }
    }
}

impl Default for Dialect {
    fn default() -> Self {
        Dialect {
            delimiter: b',',
            quote: Some(b'"'),
            has_header: true,
        }
    }
}

/// Byte-order mark found at the start of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bom {
    None,
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Bom {
    pub fn detect(head: &[u8]) -> Bom {
        if head.starts_with(b"\xEF\xBB\xBF") {
            Bom::Utf8
        } else if head.starts_with(b"\xFF\xFE") {
            Bom::Utf16Le
        } else if head.starts_with(b"\xFE\xFF") {
            Bom::Utf16Be
        } else {
            Bom::None
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Bom::None => 0,
            Bom::Utf8 => 3,
            Bom::Utf16Le | Bom::Utf16Be => 2,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Result of sniffing, including the evidence behind it.
#[derive(Clone, Debug, PartialEq)]
pub struct Sniff {
    pub dialect: Dialect,
    pub bom: Bom,
    /// Byte offset where scanning should start (after the BOM).
    pub scan_start: u64,
    /// Most common field count among sampled records.
    pub field_count: u32,
    /// Fraction of sampled records that had `field_count` fields, 0..=1.
    pub consistency: f32,
    /// Number of complete records the decision was based on.
    pub sampled_records: u32,
}

/// Delimiter candidates in preference order (ties resolve to the earlier one).
#[allow(clippy::byte_char_slices)] // the char list reads better than `*b",\t;|"`
pub const DELIMITER_CANDIDATES: [u8; 4] = [b',', b'\t', b';', b'|'];

/// Maximum number of records examined per candidate.
const MAX_SAMPLE_RECORDS: usize = 256;

/// Sniff the dialect from the first bytes of a file. `head` should be a prefix
/// of the file (a few hundred KB is plenty); `file_len` lets the sniffer know
/// whether the last sampled record was cut off by the sample boundary.
pub fn sniff(head: &[u8], file_len: u64) -> Sniff {
    let bom = Bom::detect(head);
    let scan_start = bom.len().min(head.len() as u64);
    let sample = &head[scan_start as usize..];
    let truncated = (head.len() as u64) < file_len;

    let mut best: Option<(Candidate, Dialect)> = None;
    for &delimiter in &DELIMITER_CANDIDATES {
        for quote in [Some(b'"'), None] {
            let cand = evaluate(sample, delimiter, quote, truncated);
            let dialect = Dialect {
                delimiter,
                quote,
                has_header: true,
            };
            let better = match &best {
                None => true,
                Some((b, _)) => cand.beats(b),
            };
            if better {
                best = Some((cand, dialect));
            }
        }
    }
    let (cand, mut dialect) = best.expect("at least one candidate");
    if cand.records == 0 || cand.modal_fields < 2 {
        // Nothing to go on; fall back to plain comma-separated.
        dialect = Dialect {
            delimiter: b',',
            quote: Some(b'"'),
            has_header: true,
        };
    }
    dialect.has_header = detect_header(sample, dialect, truncated);
    Sniff {
        dialect,
        bom,
        scan_start,
        field_count: cand.modal_fields,
        consistency: cand.consistency,
        sampled_records: cand.records as u32,
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    records: usize,
    modal_fields: u32,
    consistency: f32,
    quoted: bool,
    /// Records whose quoting was accepted only leniently or never closed.
    unhealthy_quotes: usize,
}

impl Candidate {
    /// Ranking, most important first:
    /// 1. multi-field structure was found at all
    /// 2. field-count consistency
    /// 3. quoting that behaved (no lenient closures / unterminated quotes);
    ///    this keeps quoting on for well-formed files even when the unquoted
    ///    scan sees more fields, and turns it off for producers that emit
    ///    stray quotes at field starts
    /// 4. more records: at equal consistency, a scan that pairs rows up by
    ///    swallowing terminators inside bogus quotes yields fewer records
    /// 5. more fields
    fn beats(&self, other: &Candidate) -> bool {
        let key = |c: &Candidate| {
            (
                c.records > 0 && c.modal_fields >= 2,
                (c.consistency * 1000.0).round() as u32,
                c.quoted && c.unhealthy_quotes == 0,
                c.records,
                c.modal_fields,
            )
        };
        key(self) > key(other)
    }
}

fn sample_spans(
    sample: &[u8],
    delimiter: u8,
    quote: Option<u8>,
    truncated: bool,
) -> Vec<RecordSpan> {
    let cfg = ScanConfig {
        delimiter,
        quote,
        count_fields: true,
    };
    let mut spans = Vec::new();
    let mut scanner = Scanner::new(cfg);
    let stopped = {
        let mut sink = |s: RecordSpan| {
            spans.push(s);
            if spans.len() >= MAX_SAMPLE_RECORDS {
                Control::Stop
            } else {
                Control::Continue
            }
        };
        scanner.feed(sample, &mut sink) == Control::Stop
    };
    if !stopped {
        let mut tail = None;
        scanner.finish(&mut |s: RecordSpan| {
            tail = Some(s);
            Control::Continue
        });
        // A record that ended exactly at the sample boundary of a longer file
        // is probably cut off; do not let it vote.
        if let Some(s) = tail
            && !truncated
        {
            spans.push(s);
        }
    }
    spans
}

fn evaluate(sample: &[u8], delimiter: u8, quote: Option<u8>, truncated: bool) -> Candidate {
    let spans = sample_spans(sample, delimiter, quote, truncated);
    if spans.is_empty() {
        return Candidate {
            records: 0,
            modal_fields: 0,
            consistency: 0.0,
            quoted: quote.is_some(),
            unhealthy_quotes: 0,
        };
    }
    let mut counts: Vec<(u32, usize)> = Vec::new();
    for s in &spans {
        match counts.iter_mut().find(|(f, _)| *f == s.fields) {
            Some((_, n)) => *n += 1,
            None => counts.push((s.fields, 1)),
        }
    }
    let (modal_fields, modal_n) = counts
        .iter()
        .copied()
        .max_by_key(|&(f, n)| (n, f))
        .expect("non-empty");
    Candidate {
        records: spans.len(),
        modal_fields,
        consistency: modal_n as f32 / spans.len() as f32,
        quoted: quote.is_some(),
        unhealthy_quotes: spans
            .iter()
            .filter(|s| s.lenient_quote || s.unterminated_quote)
            .count(),
    }
}

/// Heuristic header detection: the first record is a header when at least one
/// column looks like data below but not in the first row, or when nothing
/// looks like data anywhere and the first row's values are unique and non-empty.
fn detect_header(sample: &[u8], dialect: Dialect, truncated: bool) -> bool {
    let spans = sample_spans(sample, dialect.delimiter, dialect.quote, truncated);
    let Some(first) = spans.first() else {
        return false;
    };
    let mut head_fields: Vec<Cow<[u8]>> = Vec::new();
    split_fields(
        &sample[first.start as usize..first.end as usize],
        dialect.delimiter,
        dialect.quote,
        &mut head_fields,
    );
    if head_fields
        .iter()
        .any(|f| f.is_empty() || looks_like_data(f))
    {
        return false;
    }
    let mut unique = head_fields.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != head_fields.len() {
        return false;
    }
    // Header if any column below carries data-looking values.
    let mut fields: Vec<Cow<[u8]>> = Vec::new();
    for s in spans.iter().skip(1).take(32) {
        split_fields(
            &sample[s.start as usize..s.end as usize],
            dialect.delimiter,
            dialect.quote,
            &mut fields,
        );
        if fields.iter().any(|f| looks_like_data(f)) {
            return true;
        }
    }
    // All text everywhere: unique, non-empty first row is our best guess.
    true
}

/// Values that essentially never appear as column names.
fn looks_like_data(f: &[u8]) -> bool {
    if f.is_empty() {
        return false;
    }
    let digits = f.iter().filter(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return false;
    }
    // numbers (ints, floats, negatives)
    if f.iter()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'))
        && digits * 2 >= f.len()
    {
        return true;
    }
    // IPv4 / dotted numerics
    if f.iter().all(|b| b.is_ascii_digit() || *b == b'.')
        && f.iter().filter(|b| **b == b'.').count() == 3
    {
        return true;
    }
    // ISO-ish timestamps: 4 digits then '-' or '/'
    if f.len() >= 8 && f[..4].iter().all(u8::is_ascii_digit) && matches!(f[4], b'-' | b'/') {
        return true;
    }
    // long hex strings (hashes)
    if f.len() >= 32 && f.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(data: &[u8]) -> Sniff {
        sniff(data, data.len() as u64)
    }

    #[test]
    fn comma_with_header() {
        let r = s(b"ts,src_ip,dst_port\n2026-09-27T00:00:00Z,10.0.0.1,443\n2026-09-27T00:00:01Z,10.0.0.2,80\n");
        assert_eq!(r.dialect.delimiter, b',');
        assert_eq!(r.dialect.quote, Some(b'"'));
        assert!(r.dialect.has_header);
        assert_eq!(r.field_count, 3);
        assert_eq!(r.consistency, 1.0);
        assert_eq!(r.bom, Bom::None);
    }

    #[test]
    fn tab_and_semicolon() {
        let r = s(b"a\tb\tc\n1\t2\t3\n4\t5\t6\n");
        assert_eq!(r.dialect.delimiter, b'\t');
        assert_eq!(r.field_count, 3);
        let r = s(b"a;b\n1;2\n3;4\n");
        assert_eq!(r.dialect.delimiter, b';');
    }

    #[test]
    fn utf8_bom_is_skipped() {
        let r = s(b"\xEF\xBB\xBFa,b\n1,2\n");
        assert_eq!(r.bom, Bom::Utf8);
        assert_eq!(r.scan_start, 3);
        assert_eq!(r.dialect.delimiter, b',');
        assert!(r.dialect.has_header);
    }

    #[test]
    fn no_header_when_first_row_is_data() {
        let r = s(b"1,2,3\n4,5,6\n");
        assert!(!r.dialect.has_header);
        let r = s(b"10.0.0.1,443\n10.0.0.2,80\n");
        assert!(!r.dialect.has_header);
    }

    #[test]
    fn keeps_quoting_for_well_formed_quoted_fields() {
        // quoted delimiters: the unquoted scan sees more fields, consistently,
        // but the quoted scan is healthy and must win
        let mut data = b"id,name,city\n".to_vec();
        for i in 0..50 {
            data.extend_from_slice(format!("{i},\"Doe, J{i}\",\"Tokyo\"\n").as_bytes());
        }
        let r = s(&data);
        assert_eq!(r.dialect.delimiter, b',');
        assert_eq!(r.dialect.quote, Some(b'"'));
        assert_eq!(r.field_count, 3);
        assert!(r.dialect.has_header);
    }

    #[test]
    fn drops_quoting_for_stray_quotes() {
        // a producer that emits an unbalanced quote at a field start: with
        // quoting on, rows pair up (still "consistent"), but every closure is
        // lenient, so quoting must be turned off
        let mut data = b"a\tb\tc\n".to_vec();
        for i in 0..50 {
            data.extend_from_slice(format!("{i}\t\"broken\tx{i}\n").as_bytes());
        }
        let r = s(&data);
        assert_eq!(r.dialect.delimiter, b'\t');
        assert_eq!(r.dialect.quote, None);
        assert_eq!(r.field_count, 3);
        assert_eq!(r.sampled_records, 51);
    }

    #[test]
    fn truncated_tail_record_does_not_vote() {
        let full = b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n";
        let head = &full[..full.len() - 3]; // cuts "7,8,9\n" to "7,8"
        let r = sniff(head, full.len() as u64);
        assert_eq!(r.field_count, 3);
        assert_eq!(r.consistency, 1.0);
        assert_eq!(r.sampled_records, 3);
    }

    #[test]
    fn empty_input() {
        let r = s(b"");
        assert_eq!(r.dialect.delimiter, b',');
        assert_eq!(r.sampled_records, 0);
        assert!(!r.dialect.has_header);
    }
}
