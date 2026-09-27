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
        match quote {
            Some(q) if i < n && raw[i] == q => {
                i = quoted_field(raw, i + 1, delimiter, q, out);
            }
            _ => {
                let end = memchr(delimiter, &raw[i..]).map_or(n, |p| i + p);
                out.push(Cow::Borrowed(&raw[i..end]));
                i = end;
            }
        }
        if i < n && raw[i] == delimiter {
            i += 1;
            // a trailing delimiter yields one more (empty) field
        } else {
            break;
        }
    }
}

/// Parse a quoted field whose opening quote sits just before `i`.
/// Returns the index of the byte following the field (a delimiter or `raw.len()`).
fn quoted_field<'a>(
    raw: &'a [u8],
    mut i: usize,
    delimiter: u8,
    q: u8,
    out: &mut Vec<Cow<'a, [u8]>>,
) -> usize {
    let n = raw.len();
    let mut seg_start = i;
    let mut owned: Option<Vec<u8>> = None;
    loop {
        let Some(p) = memchr(q, &raw[i..]) else {
            // Unterminated quote: everything to the end is the field.
            let seg = &raw[seg_start..];
            out.push(match owned {
                None => Cow::Borrowed(seg),
                Some(mut v) => {
                    v.extend_from_slice(seg);
                    Cow::Owned(v)
                }
            });
            return n;
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
        out.push(match owned {
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
        });
        return tail_end;
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
    fn borrows_when_possible() {
        let mut out = Vec::new();
        split_fields(b"a,\"b\",\"c\"\"d\"", b',', Some(b'"'), &mut out);
        assert!(matches!(out[0], Cow::Borrowed(_)));
        assert!(matches!(out[1], Cow::Borrowed(_)));
        assert!(matches!(out[2], Cow::Owned(_)));
    }
}
