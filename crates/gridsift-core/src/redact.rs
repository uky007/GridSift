//! Column redaction applied while exporting.
//!
//! A [`Redactor`] rewrites only the fields it is told to; every other field
//! is copied with its original bytes and quoting. The policy (which columns,
//! which method, which parameters) is serialisable so the manifest can
//! record exactly what was done; the HMAC key never is — only a fingerprint
//! of it, so a later export can be checked for having used the same key.
//!
//! Deterministic pseudonymisation (`hmac`) keeps correlation across rows and
//! files, which is what an analyst usually wants from redacted evidence, but
//! it is *not* an anonymity guarantee: low-entropy values can still be
//! guessed by anyone who obtains the key or can enumerate candidates.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dialect::Dialect;
use crate::hash::hex;
use crate::record::field_spans;

/// How a column is redacted. Serialised into the manifest; carries no secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RedactMethod {
    /// Remove the column (from the header too).
    Drop,
    /// Replace every non-empty value with `replacement`.
    Mask { replacement: String },
    /// Keep the first `keep` characters, replace the rest with `fill`.
    Partial { keep: usize, fill: char },
    /// Zero the host bits of an IP address (`10.1.243.150` → `10.1.0.0` for
    /// `bits: 16`); values that are not IPs are masked.
    IpPrefix { bits: u8 },
    /// Deterministic pseudonym: first `length` hex chars of
    /// HMAC-SHA256(key, value). Only the key's fingerprint is recorded.
    Hmac {
        length: usize,
        key_fingerprint: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactRule {
    pub column: usize,
    pub name: String,
    #[serde(flatten)]
    pub method: RedactMethod,
}

/// The serialisable half of a redaction: what will be recorded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    pub rules: Vec<RedactRule>,
}

pub const DEFAULT_MASK: &str = "[REDACTED]";
pub const DEFAULT_HMAC_LENGTH: usize = 16;

/// `sha256(key)` truncated to 16 hex chars: enough to recognise a key, not
/// to recover it.
pub fn key_fingerprint(key: &[u8]) -> String {
    hex(&Sha256::digest(key))[..16].to_string()
}

/// A compiled redaction: the policy plus the secret it needs.
pub struct Redactor {
    dialect: Dialect,
    policy: RedactionPolicy,
    /// Rules indexed by column for fast lookup.
    by_column: Vec<Option<usize>>,
    hmac_key: Option<Vec<u8>>,
    drops_any: bool,
}

impl std::fmt::Debug for Redactor {
    /// The key is deliberately not shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("policy", &self.policy)
            .field("has_key", &self.hmac_key.is_some())
            .finish()
    }
}

impl Redactor {
    /// Build from rules. An HMAC rule without a key is an error; the rule's
    /// `key_fingerprint` is filled in from the key.
    pub fn new(
        dialect: Dialect,
        mut rules: Vec<RedactRule>,
        hmac_key: Option<&[u8]>,
    ) -> Result<Redactor, String> {
        let mut by_column: Vec<Option<usize>> = Vec::new();
        for (i, r) in rules.iter_mut().enumerate() {
            match &mut r.method {
                RedactMethod::Hmac {
                    length,
                    key_fingerprint: fp,
                } => {
                    let Some(key) = hmac_key else {
                        return Err(format!("column {:?}: hmac needs a key", r.name));
                    };
                    if key.is_empty() {
                        return Err("hmac key must not be empty".into());
                    }
                    if *length == 0 || *length > 64 {
                        return Err(format!("column {:?}: hmac length must be 1..=64", r.name));
                    }
                    *fp = key_fingerprint(key);
                }
                RedactMethod::IpPrefix { bits } if *bits > 128 => {
                    return Err(format!("column {:?}: prefix bits must be 0..=128", r.name));
                }
                _ => {}
            }
            if by_column.len() <= r.column {
                by_column.resize(r.column + 1, None);
            }
            if by_column[r.column].is_some() {
                return Err(format!("column {} has two redaction rules", r.column));
            }
            by_column[r.column] = Some(i);
        }
        let drops_any = rules.iter().any(|r| r.method == RedactMethod::Drop);
        Ok(Redactor {
            dialect,
            policy: RedactionPolicy { rules },
            by_column,
            hmac_key: hmac_key.map(<[u8]>::to_vec),
            drops_any,
        })
    }

    pub fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    pub fn is_empty(&self) -> bool {
        self.policy.rules.is_empty()
    }

    fn rule_for(&self, column: usize) -> Option<&RedactRule> {
        self.by_column
            .get(column)
            .copied()
            .flatten()
            .map(|i| &self.policy.rules[i])
    }

    /// Rewrite one record's content bytes into `out` (cleared first).
    /// Untouched fields keep their exact bytes and quoting.
    pub fn render(&self, raw: &[u8], out: &mut Vec<u8>) {
        out.clear();
        self.render_with(raw, out, false);
    }

    /// Rewrite the header record: dropped columns disappear, others are kept.
    pub fn render_header(&self, raw: &[u8], out: &mut Vec<u8>) {
        out.clear();
        self.render_with(raw, out, true);
    }

    fn render_with(&self, raw: &[u8], out: &mut Vec<u8>, header: bool) {
        let d = self.dialect;
        let mut spans = Vec::new();
        field_spans(raw, d.delimiter, d.quote, &mut spans);
        let mut first = true;
        for (i, &(s, e)) in spans.iter().enumerate() {
            let rule = self.rule_for(i);
            if matches!(rule.map(|r| &r.method), Some(RedactMethod::Drop)) {
                continue;
            }
            if !first {
                out.push(d.delimiter);
            }
            first = false;
            match rule {
                Some(r) if !header => {
                    let mut value = Vec::new();
                    unquote(&raw[s..e], d.quote, &mut value);
                    let replaced = self.apply(&r.method, &value);
                    write_field(&replaced, d, out);
                }
                _ => out.extend_from_slice(&raw[s..e]),
            }
        }
        // a record whose every field was dropped still needs to be a record
        if first && !self.drops_any {
            out.extend_from_slice(raw);
        }
    }

    fn apply(&self, method: &RedactMethod, value: &[u8]) -> Vec<u8> {
        if value.is_empty() {
            return Vec::new();
        }
        match method {
            RedactMethod::Drop => Vec::new(),
            RedactMethod::Mask { replacement } => replacement.as_bytes().to_vec(),
            RedactMethod::Partial { keep, fill } => {
                let mut fill_buf = [0u8; 4];
                let fill = fill.encode_utf8(&mut fill_buf).as_bytes().to_vec();
                match std::str::from_utf8(value) {
                    Ok(s) => {
                        let mut out = Vec::with_capacity(value.len());
                        for (n, ch) in s.chars().enumerate() {
                            if n < *keep {
                                let mut b = [0u8; 4];
                                out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                            } else {
                                out.extend_from_slice(&fill);
                            }
                        }
                        out
                    }
                    Err(_) => {
                        let mut out = value[..(*keep).min(value.len())].to_vec();
                        for _ in *keep..value.len() {
                            out.extend_from_slice(&fill);
                        }
                        out
                    }
                }
            }
            RedactMethod::IpPrefix { bits } => match std::str::from_utf8(value).map(str::trim) {
                Ok(s) => {
                    if let Ok(v4) = Ipv4Addr::from_str(s) {
                        let bits = (*bits).min(32);
                        let mask: u32 = if bits == 0 {
                            0
                        } else {
                            u32::MAX << (32 - bits)
                        };
                        Ipv4Addr::from(u32::from(v4) & mask)
                            .to_string()
                            .into_bytes()
                    } else if let Ok(v6) = Ipv6Addr::from_str(s) {
                        let bits = (*bits).min(128);
                        let mask: u128 = if bits == 0 {
                            0
                        } else {
                            u128::MAX << (128 - bits)
                        };
                        Ipv6Addr::from(u128::from(v6) & mask)
                            .to_string()
                            .into_bytes()
                    } else {
                        DEFAULT_MASK.as_bytes().to_vec()
                    }
                }
                Err(_) => DEFAULT_MASK.as_bytes().to_vec(),
            },
            RedactMethod::Hmac { length, .. } => {
                let key = self.hmac_key.as_deref().unwrap_or(b"");
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(value);
                let tag = mac.finalize().into_bytes();
                hex(&tag)[..*length].to_string().into_bytes()
            }
        }
    }
}

/// Field value from its raw extent: strip surrounding quotes, unescape `""`.
fn unquote(raw: &[u8], quote: Option<u8>, out: &mut Vec<u8>) {
    out.clear();
    match quote {
        Some(q) if raw.len() >= 2 && raw[0] == q && raw[raw.len() - 1] == q => {
            let inner = &raw[1..raw.len() - 1];
            let mut i = 0;
            while i < inner.len() {
                out.push(inner[i]);
                if inner[i] == q && inner.get(i + 1) == Some(&q) {
                    i += 1;
                }
                i += 1;
            }
        }
        _ => out.extend_from_slice(raw),
    }
}

/// Write a field value with the minimal quoting the dialect needs.
fn write_field(value: &[u8], d: Dialect, out: &mut Vec<u8>) {
    let needs_quote = value
        .iter()
        .any(|&b| b == d.delimiter || Some(b) == d.quote || b == b'\n' || b == b'\r');
    match d.quote {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<RedactRule> {
        vec![
            RedactRule {
                column: 1,
                name: "user".into(),
                method: RedactMethod::Hmac {
                    length: 12,
                    key_fingerprint: String::new(),
                },
            },
            RedactRule {
                column: 2,
                name: "ip".into(),
                method: RedactMethod::IpPrefix { bits: 16 },
            },
            RedactRule {
                column: 3,
                name: "email".into(),
                method: RedactMethod::Mask {
                    replacement: DEFAULT_MASK.into(),
                },
            },
            RedactRule {
                column: 4,
                name: "secret".into(),
                method: RedactMethod::Drop,
            },
            RedactRule {
                column: 5,
                name: "note".into(),
                method: RedactMethod::Partial { keep: 3, fill: '*' },
            },
        ]
    }

    fn render(r: &Redactor, raw: &[u8]) -> String {
        let mut out = Vec::new();
        r.render(raw, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn methods() {
        let r = Redactor::new(Dialect::default(), rules(), Some(b"k3y")).unwrap();
        let line = b"2026-09-27,alice,10.1.243.150,alice@example.com,topsecret,hello world,\"kept, as is\"";
        let got = render(&r, line);
        let f: Vec<&str> = got.split(',').collect();
        assert_eq!(f[0], "2026-09-27");
        assert_eq!(f[1].len(), 12);
        assert!(f[1].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(f[2], "10.1.0.0");
        assert_eq!(f[3], DEFAULT_MASK);
        // "topsecret" is gone entirely
        assert_eq!(f[4], "hel********");
        assert_eq!(&got[got.len() - 13..], "\"kept, as is\"");
        assert_eq!(got.matches(',').count(), 6);
        // deterministic, key-dependent
        let again = render(&r, line);
        assert_eq!(got, again);
        let other = Redactor::new(Dialect::default(), rules(), Some(b"other")).unwrap();
        assert_ne!(render(&other, line).split(',').nth(1), Some(f[1]));
        // fingerprint recorded, key not
        let json = serde_json::to_string(r.policy()).unwrap();
        assert!(json.contains(&key_fingerprint(b"k3y")));
        assert!(!json.contains("k3y"));
        assert!(json.contains("\"method\":\"ip_prefix\""));
    }

    #[test]
    fn header_and_empties() {
        let r = Redactor::new(Dialect::default(), rules(), Some(b"k")).unwrap();
        let mut out = Vec::new();
        r.render_header(b"ts,user,ip,email,secret,note,free", &mut out);
        assert_eq!(out, b"ts,user,ip,email,note,free");
        // empty values stay empty, short records are fine
        assert_eq!(render(&r, b"t,,,,x,"), "t,,,,");
        assert_eq!(render(&r, b"t"), "t");
        let got = render(&r, b"t,bob");
        assert!(got.starts_with("t,") && got.len() == 2 + 12, "{got}");
    }

    #[test]
    fn quoting_of_rewritten_fields() {
        let d = Dialect::default();
        let r = Redactor::new(
            d,
            vec![RedactRule {
                column: 0,
                name: "a".into(),
                method: RedactMethod::Mask {
                    replacement: "x,\"y\"".into(),
                },
            }],
            None,
        )
        .unwrap();
        assert_eq!(render(&r, b"\"orig, value\",b"), "\"x,\"\"y\"\"\",b");
        // an original quoted field passes through untouched
        assert_eq!(render(&r, b"v,\"q\"\"q\""), "\"x,\"\"y\"\"\",\"q\"\"q\"");
    }

    #[test]
    fn ipv6_and_invalid_ips() {
        let r = Redactor::new(
            Dialect::default(),
            vec![RedactRule {
                column: 0,
                name: "ip".into(),
                method: RedactMethod::IpPrefix { bits: 48 },
            }],
            None,
        )
        .unwrap();
        assert_eq!(render(&r, b"2001:db8:abcd:1234::1"), "2001:db8:abcd::");
        assert_eq!(render(&r, b"not-an-ip"), DEFAULT_MASK);
        // a prefix longer than 32 keeps an IPv4 address whole
        assert_eq!(render(&r, b"10.9.8.7"), "10.9.8.7");
        let r24 = Redactor::new(
            Dialect::default(),
            vec![RedactRule {
                column: 0,
                name: "ip".into(),
                method: RedactMethod::IpPrefix { bits: 24 },
            }],
            None,
        )
        .unwrap();
        assert_eq!(render(&r24, b"10.9.8.7"), "10.9.8.0");
        assert_eq!(render(&r24, b" 10.9.8.7 "), "10.9.8.0");
    }

    #[test]
    fn validation() {
        let hmac = |key: Option<&[u8]>| {
            Redactor::new(
                Dialect::default(),
                vec![RedactRule {
                    column: 0,
                    name: "u".into(),
                    method: RedactMethod::Hmac {
                        length: 16,
                        key_fingerprint: String::new(),
                    },
                }],
                key,
            )
        };
        assert!(hmac(None).is_err());
        assert!(hmac(Some(b"")).is_err());
        assert!(hmac(Some(b"k")).is_ok());
        let dup = Redactor::new(
            Dialect::default(),
            vec![
                RedactRule {
                    column: 0,
                    name: "a".into(),
                    method: RedactMethod::Drop,
                },
                RedactRule {
                    column: 0,
                    name: "a".into(),
                    method: RedactMethod::Drop,
                },
            ],
            None,
        );
        assert!(dup.is_err());
        assert_eq!(key_fingerprint(b"abc").len(), 16);
    }
}
