//! Field splitting for one logical record.
//!
//! Operates on the exact content span reported by the scanner (terminator
//! excluded) and applies the same lenient quoting rules, so the field count
//! here always agrees with `RecordSpan::fields`.

use std::borrow::Cow;

use memchr::memchr;

/// Split `raw` into fields. Fields that need no unescaping borrow from `raw`;
/// only fields containing `""` (or lenient trailing bytes after a closing
/// quote) allocate.
pub fn split_fields<'a>(
    raw: &'a [u8],
    delimiter: u8,
    quote: Option<u8>,
    out: &mut Vec<Cow<'a, [u8]>>,
) {
    out.clear();
    let n = raw.len();
    let mut i = 0usize;
    loop {
        let (field, next) = parse_field(raw, i, delimiter, quote);
        out.push(field);
        i = next;
        if i < n && raw[i] == delimiter {
            i += 1;
            // a trailing delimiter yields one more (empty) field
        } else {
            break;
        }
    }
}

/// Write a field value with the minimal quoting the dialect needs (quote
/// when it contains the delimiter, the quote byte, CR or LF; double quotes).
pub fn write_field(value: &[u8], delimiter: u8, quote: Option<u8>, out: &mut Vec<u8>) {
    let needs_quote = value
        .iter()
        .any(|&b| b == delimiter || Some(b) == quote || b == b'\n' || b == b'\r');
    match quote {
        Some(q) if needs_quote => {
            out.push(q);
            for &b in value {
                if b == q {
                    out.push(q);
                }
                out.push(b);
            }
            out.push(q);
        }
        _ => out.extend_from_slice(value),
    }
}

/// Raw extent `(start, end)` of every field, quotes included, so a record
/// can be rewritten field by field while untouched fields keep their exact
/// bytes.
pub fn field_spans(raw: &[u8], delimiter: u8, quote: Option<u8>, out: &mut Vec<(usize, usize)>) {
    out.clear();
    let n = raw.len();
    let mut i = 0usize;
    loop {
        let end = skip_field(raw, i, delimiter, quote);
        out.push((i, end));
        i = end;
        if i < n && raw[i] == delimiter {
            i += 1;
        } else {
            break;
        }
    }
}

/// The `k`-th field (0-based) of `raw`, or `None` if the record has fewer
/// fields. Earlier fields are skipped without being materialised.
pub fn nth_field(raw: &[u8], delimiter: u8, quote: Option<u8>, k: usize) -> Option<Cow<'_, [u8]>> {
    let n = raw.len();
    let mut i = 0usize;
    for _ in 0..k {
        i = skip_field(raw, i, delimiter, quote);
        if i < n && raw[i] == delimiter {
            i += 1;
        } else {
            return None;
        }
    }
    Some(parse_field(raw, i, delimiter, quote).0)
}

/// Parse the field starting at `i`; returns it and the index of the byte
/// following it (a delimiter or `raw.len()`).
fn parse_field(raw: &[u8], i: usize, delimiter: u8, quote: Option<u8>) -> (Cow<'_, [u8]>, usize) {
    let n = raw.len();
    match quote {
        Some(q) if i < n && raw[i] == q => quoted_field(raw, i + 1, delimiter, q),
        _ => {
            let end = memchr(delimiter, &raw[i..]).map_or(n, |p| i + p);
            (Cow::Borrowed(&raw[i..end]), end)
        }
    }
}

/// Index of the byte following the field starting at `i`, without building
/// the field.
fn skip_field(raw: &[u8], i: usize, delimiter: u8, quote: Option<u8>) -> usize {
    let n = raw.len();
    match quote {
        Some(q) if i < n && raw[i] == q => {
            let mut j = i + 1;
            loop {
                let Some(p) = memchr(q, &raw[j..]) else {
                    return n; // unterminated quote swallows the rest
                };
                let qpos = j + p;
                if raw.get(qpos + 1) == Some(&q) {
                    j = qpos + 2; // escaped quote
                    continue;
                }
                // closing quote; lenient tail runs to the delimiter
                return memchr(delimiter, &raw[qpos + 1..]).map_or(n, |p| qpos + 1 + p);
            }
        }
        _ => memchr(delimiter, &raw[i..]).map_or(n, |p| i + p),
    }
}

/// Parse a quoted field whose opening quote sits just before `i`.
/// Returns the field and the index of the byte following it.
fn quoted_field(raw: &[u8], mut i: usize, delimiter: u8, q: u8) -> (Cow<'_, [u8]>, usize) {
    let n = raw.len();
    let mut seg_start = i;
    let mut owned: Option<Vec<u8>> = None;
    loop {
        let Some(p) = memchr(q, &raw[i..]) else {
            // Unterminated quote: everything to the end is the field.
            let seg = &raw[seg_start..];
            let field = match owned {
                None => Cow::Borrowed(seg),
                Some(mut v) => {
                    v.extend_from_slice(seg);
                    Cow::Owned(v)
                }
            };
            return (field, n);
        };
        let qpos = i + p;
        if raw.get(qpos + 1) == Some(&q) {
            // `""` -> keep one quote, continue inside the quoted field
            owned
                .get_or_insert_with(Vec::new)
                .extend_from_slice(&raw[seg_start..=qpos]);
            i = qpos + 2;
            seg_start = i;
            continue;
        }
        // Closing quote. Lenient rule: literal bytes up to the delimiter are
        // appended to the field.
        let seg = &raw[seg_start..qpos];
        let tail_start = qpos + 1;
        let tail_end = memchr(delimiter, &raw[tail_start..]).map_or(n, |p| tail_start + p);
        let tail = &raw[tail_start..tail_end];
        let field = match owned {
            None if tail.is_empty() => Cow::Borrowed(seg),
            None => {
                let mut v = Vec::with_capacity(seg.len() + tail.len());
                v.extend_from_slice(seg);
                v.extend_from_slice(tail);
                Cow::Owned(v)
            }
            Some(mut v) => {
                v.extend_from_slice(seg);
                v.extend_from_slice(tail);
                Cow::Owned(v)
            }
        };
        return (field, tail_end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(raw: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        split_fields(raw, b',', Some(b'"'), &mut out);
        out.into_iter().map(|c| c.into_owned()).collect()
    }

    fn v(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn plain() {
        assert_eq!(split(b"a,b,c"), v(&["a", "b", "c"]));
        assert_eq!(split(b""), v(&[""]));
        assert_eq!(split(b","), v(&["", ""]));
        assert_eq!(split(b"a,"), v(&["a", ""]));
        assert_eq!(split(b",a"), v(&["", "a"]));
        assert_eq!(split(b",,"), v(&["", "", ""]));
    }

    #[test]
    fn quoted() {
        assert_eq!(split(b"\"a,b\",c"), v(&["a,b", "c"]));
        assert_eq!(split(b"\"a\"\"b\",c"), v(&["a\"b", "c"]));
        assert_eq!(split(b"\"\",\"\""), v(&["", ""]));
        assert_eq!(split(b"\"x\ny\",z"), v(&["x\ny", "z"]));
        assert_eq!(split(b"\"\"\"\""), v(&["\""]));
        assert_eq!(split(b"\"\"\"\"\"\""), v(&["\"\""]));
    }

    #[test]
    fn lenient_cases() {
        // quote in the middle of an unquoted field is literal
        assert_eq!(split(b"a\"b,c"), v(&["a\"b", "c"]));
        // bytes after a closing quote are literal
        assert_eq!(split(b"\"a\"b,c"), v(&["ab", "c"]));
        assert_eq!(split(b"\"a\"\"b\"c,d"), v(&["a\"bc", "d"]));
        // unterminated quote swallows the rest, including delimiters
        assert_eq!(split(b"\"a,b"), v(&["a,b"]));
        assert_eq!(split(b"x,\"a,b"), v(&["x", "a,b"]));
    }

    #[test]
    fn no_quote_mode() {
        let mut out = Vec::new();
        split_fields(b"\"a\",b", b',', None, &mut out);
        assert_eq!(
            out.into_iter().map(|c| c.into_owned()).collect::<Vec<_>>(),
            v(&["\"a\"", "b"])
        );
    }

    #[test]
    fn field_spans_cover_the_record() {
        let cases: &[&[u8]] = &[
            b"a,b,c",
            b"",
            b",",
            b"a,",
            b"\"a,b\",c",
            b"\"a\"\"b\",c,\"\"",
            b"\"a\"b,c",
            b"\"unterminated,x",
        ];
        for raw in cases {
            let mut spans = Vec::new();
            field_spans(raw, b',', Some(b'"'), &mut spans);
            let mut all = Vec::new();
            split_fields(raw, b',', Some(b'"'), &mut all);
            assert_eq!(spans.len(), all.len(), "{:?}", String::from_utf8_lossy(raw));
            // spans tile the record, separated by single delimiters
            let mut expect = 0;
            for (s, e) in &spans {
                assert_eq!(*s, expect);
                expect = e + 1;
            }
            assert_eq!(expect, raw.len() + 1);
            // an unquoted field's span is its value
            for ((s, e), v) in spans.iter().zip(&all) {
                if !raw[*s..*e].starts_with(b"\"") {
                    assert_eq!(&raw[*s..*e], v.as_ref());
                }
            }
        }
    }

    #[test]
    fn nth_field_agrees_with_split() {
        let cases: &[&[u8]] = &[
            b"a,b,c",
            b"",
            b",",
            b"a,",
            b",,",
            b"\"a,b\",c",
            b"\"a\"\"b\",c,\"\"",
            b"x,\"line\nbreak\",\"q\"\"\"",
            b"\"a\"b,c",
            b"\"unterminated,x",
            b"a\"b,\"c",
            b"one",
        ];
        for raw in cases {
            let mut all = Vec::new();
            split_fields(raw, b',', Some(b'"'), &mut all);
            for k in 0..all.len() + 2 {
                let got = nth_field(raw, b',', Some(b'"'), k);
                assert_eq!(
                    got.as_deref(),
                    all.get(k).map(|c| c.as_ref()),
                    "record {:?} field {k}",
                    String::from_utf8_lossy(raw)
                );
            }
        }
    }

    #[test]
    fn borrows_when_possible() {
        let mut out = Vec::new();
        split_fields(b"a,\"b\",\"c\"\"d\"", b',', Some(b'"'), &mut out);
        assert!(matches!(out[0], Cow::Borrowed(_)));
        assert!(matches!(out[1], Cow::Borrowed(_)));
        assert!(matches!(out[2], Cow::Owned(_)));
    }
}
