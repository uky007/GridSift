//! Deterministic synthetic datasets for benchmarks and demos.
//!
//! The same `(profile, seed)` always yields the same bytes, so benchmark
//! inputs can be regenerated anywhere and identified by hash.

use std::io::{self, BufWriter, Write};
use std::str::FromStr;

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::hash::hex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Proxy/firewall-like log: 13 columns, ~230 bytes per row, quoted UA.
    Narrow,
    /// EDR-export-like: 150 mostly numeric/short columns.
    Wide,
    /// CSV torture: embedded delimiters, quotes, LF/CRLF inside quotes,
    /// empty quoted fields, trailing delimiters. Every row still has 3 fields.
    Quotes,
    /// Like `Narrow` but ~10% of rows have a missing or extra field.
    Ragged,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::Narrow,
        Profile::Wide,
        Profile::Quotes,
        Profile::Ragged,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Profile::Narrow => "narrow",
            Profile::Wide => "wide",
            Profile::Quotes => "quotes",
            Profile::Ragged => "ragged",
        }
    }
}

impl FromStr for Profile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Profile::ALL
            .iter()
            .copied()
            .find(|p| p.name() == s)
            .ok_or_else(|| {
                format!("unknown profile {s:?}; expected one of narrow, wide, quotes, ragged")
            })
    }
}

/// How much to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Rows(u64),
    /// Stop after the row that crosses this many bytes.
    Bytes(u64),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenStats {
    pub rows: u64,
    pub bytes: u64,
}

const WIDE_COLUMNS: usize = 150;

pub struct Generator {
    profile: Profile,
    rng: ChaCha8Rng,
    row: u64,
    /// Unix seconds of the next event.
    clock: u64,
    domains: Vec<String>,
    users: Vec<String>,
    paths: Vec<&'static str>,
    agents: Vec<&'static str>,
}

impl Generator {
    pub fn new(profile: Profile, seed: u64) -> Generator {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let domains = (0..2000).map(|_| random_domain(&mut rng)).collect();
        let users = (0..500).map(|i| format!("user{i:04}")).collect();
        Generator {
            profile,
            rng,
            row: 0,
            clock: 1_790_000_000, // 2026-09-21T14:13:20Z
            domains,
            users,
            paths: vec![
                "/",
                "/index.html",
                "/api/v1/login",
                "/api/v1/logout",
                "/static/app.js",
                "/images/logo.png",
                "/update/check",
                "/dl/setup.exe",
                "/c2/beacon",
                "/robots.txt",
            ],
            agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
                "curl/8.7.1",
                "python-requests/2.32.3",
                "Microsoft-Delivery-Optimization/10.0",
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                "\"quoted\", agent, with, commas",
                "",
            ],
        }
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Header line (with trailing `\n`).
    pub fn header(&self) -> String {
        match self.profile {
            Profile::Narrow | Profile::Ragged => {
                "timestamp,src_ip,dst_ip,dst_port,proto,host,path,status,bytes,user,action,user_agent,sha256\n".to_string()
            }
            Profile::Wide => {
                let mut s = String::new();
                for i in 0..WIDE_COLUMNS {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!("c{i:03}"));
                }
                s.push('\n');
                s
            }
            Profile::Quotes => "id,message,note\n".to_string(),
        }
    }

    /// Append one row (with terminator) to `out`.
    pub fn write_row(&mut self, out: &mut Vec<u8>) {
        match self.profile {
            Profile::Narrow => self.narrow_row(out, false),
            Profile::Ragged => self.narrow_row(out, true),
            Profile::Wide => self.wide_row(out),
            Profile::Quotes => self.quotes_row(out),
        }
        self.row += 1;
    }

    /// Generate header + rows into `w` until `target` is met. `progress`
    /// receives cumulative (bytes, rows) roughly every 8 MiB.
    pub fn generate<W: Write>(
        &mut self,
        w: W,
        target: Target,
        mut progress: Option<&mut dyn FnMut(u64, u64)>,
    ) -> io::Result<GenStats> {
        let mut w = BufWriter::with_capacity(4 << 20, w);
        let header = self.header();
        w.write_all(header.as_bytes())?;
        let mut stats = GenStats {
            rows: 0,
            bytes: header.len() as u64,
        };
        let mut buf = Vec::with_capacity(64 << 10);
        let mut since_report = 0u64;
        loop {
            let done = match target {
                Target::Rows(n) => stats.rows >= n,
                Target::Bytes(n) => stats.bytes >= n,
            };
            if done {
                break;
            }
            buf.clear();
            // batch rows to amortise the write call
            let batch = match target {
                Target::Rows(n) => (n - stats.rows).min(256),
                Target::Bytes(_) => 256,
            };
            for _ in 0..batch {
                self.write_row(&mut buf);
                stats.rows += 1;
                if let Target::Bytes(n) = target {
                    if stats.bytes + buf.len() as u64 >= n {
                        break;
                    }
                }
            }
            w.write_all(&buf)?;
            stats.bytes += buf.len() as u64;
            since_report += buf.len() as u64;
            if since_report >= 8 << 20 {
                since_report = 0;
                if let Some(p) = &mut progress {
                    p(stats.bytes, stats.rows);
                }
            }
        }
        w.flush()?;
        if let Some(p) = &mut progress {
            p(stats.bytes, stats.rows);
        }
        Ok(stats)
    }

    fn narrow_row(&mut self, out: &mut Vec<u8>, ragged: bool) {
        let rng = &mut self.rng;
        self.clock += rng.random_range(0..3);
        write_iso8601(out, self.clock);
        out.push(b',');
        write_internal_ip(out, rng);
        out.push(b',');
        write_public_ip(out, rng);
        out.push(b',');
        let port: u16 = match rng.random_range(0..10) {
            0..=5 => 443,
            6..=7 => 80,
            8 => 8080,
            _ => rng.random_range(1024..65535),
        };
        push_int(out, port);
        out.push(b',');
        out.extend_from_slice(if rng.random_bool(0.9) { b"tcp" } else { b"udp" });
        out.push(b',');
        let d = &self.domains[rng.random_range(0..self.domains.len())];
        if rng.random_bool(0.3) {
            out.extend_from_slice(if rng.random_bool(0.5) {
                b"www."
            } else {
                b"cdn."
            });
        }
        out.extend_from_slice(d.as_bytes());
        out.push(b',');
        let path = self.paths[rng.random_range(0..self.paths.len())];
        out.extend_from_slice(path.as_bytes());
        out.push(b',');
        let status: u16 = match rng.random_range(0..20) {
            0..=15 => 200,
            16 => 301,
            17 => 403,
            18 => 404,
            _ => 500,
        };
        push_int(out, status);
        out.push(b',');
        push_int(out, rng.random_range(0u32..2_000_000));
        out.push(b',');
        if ragged && rng.random_bool(0.05) {
            // missing field: skip the user
        } else {
            out.extend_from_slice(self.users[rng.random_range(0..self.users.len())].as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(if rng.random_bool(0.97) {
            b"allow"
        } else {
            b"deny"
        });
        out.push(b',');
        let ua = self.agents[rng.random_range(0..self.agents.len())];
        write_quoted(out, ua.as_bytes());
        out.push(b',');
        let mut h = [0u8; 32];
        rng.fill(&mut h[..]);
        out.extend_from_slice(hex(&h).as_bytes());
        if ragged && rng.random_bool(0.05) {
            out.extend_from_slice(b",extra");
        }
        out.push(b'\n');
    }

    fn wide_row(&mut self, out: &mut Vec<u8>) {
        let rng = &mut self.rng;
        self.clock += 1;
        for i in 0..WIDE_COLUMNS {
            if i > 0 {
                out.push(b',');
            }
            match i % 5 {
                0 => write_iso8601(out, self.clock),
                1 => push_int(out, rng.random::<u32>()),
                2 => {
                    push_int(out, rng.random_range(0u32..1000));
                    out.push(b'.');
                    push_int(out, rng.random_range(0u32..100));
                }
                3 => out.extend_from_slice(if rng.random_bool(0.5) {
                    b"true"
                } else {
                    b"false"
                }),
                _ => {
                    let n = rng.random_range(3..12);
                    for _ in 0..n {
                        out.push(b'a' + rng.random_range(0u8..26));
                    }
                }
            }
        }
        out.push(b'\n');
    }

    fn quotes_row(&mut self, out: &mut Vec<u8>) {
        let rng = &mut self.rng;
        push_int(out, self.row);
        out.push(b',');
        match rng.random_range(0..8) {
            0 => out.extend_from_slice(b"plain text"),
            1 => out.extend_from_slice(b"\"has, comma\""),
            2 => out.extend_from_slice(b"\"has \"\"quote\"\" inside\""),
            3 => out.extend_from_slice(b"\"line one\nline two\""),
            4 => out.extend_from_slice(b"\"crlf inside\r\nsecond\""),
            5 => out.extend_from_slice(b"\"\""),
            6 => {}
            _ => {
                out.push(b'"');
                let n = rng.random_range(0..2000);
                for _ in 0..n {
                    let b = rng.random_range(0u8..40);
                    match b {
                        0 => out.extend_from_slice(b"\"\""),
                        1 => out.push(b','),
                        2 => out.push(b'\n'),
                        _ => out.push(b'a' + (b % 26)),
                    }
                }
                out.push(b'"');
            }
        }
        out.push(b',');
        if rng.random_bool(0.5) {
            out.extend_from_slice(b"note");
        }
        out.extend_from_slice(if rng.random_bool(0.5) { b"\n" } else { b"\r\n" });
    }
}

fn random_domain(rng: &mut ChaCha8Rng) -> String {
    const SYL: [&str; 24] = [
        "ac", "ba", "cor", "da", "el", "fi", "go", "ha", "in", "ju", "ka", "lo", "ma", "ne", "or",
        "pa", "qu", "ra", "so", "ta", "ul", "va", "wi", "zo",
    ];
    const TLD: [&str; 8] = ["com", "net", "org", "io", "co.jp", "co.uk", "xyz", "info"];
    let n = rng.random_range(2..5);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(SYL[rng.random_range(0..SYL.len())]);
    }
    s.push('.');
    s.push_str(TLD[rng.random_range(0..TLD.len())]);
    s
}

fn write_internal_ip(out: &mut Vec<u8>, rng: &mut ChaCha8Rng) {
    out.extend_from_slice(b"10.");
    push_int(out, rng.random_range(0u8..16));
    out.push(b'.');
    push_int(out, rng.random::<u8>());
    out.push(b'.');
    push_int(out, rng.random_range(1u8..255));
}

fn write_public_ip(out: &mut Vec<u8>, rng: &mut ChaCha8Rng) {
    // avoid the usual private/special ranges in the first octet
    let a = loop {
        let a: u8 = rng.random_range(1..224);
        if !matches!(a, 10 | 127 | 169 | 172 | 192) {
            break a;
        }
    };
    push_int(out, a);
    for _ in 0..3 {
        out.push(b'.');
        push_int(out, rng.random::<u8>());
    }
}

fn write_quoted(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    for &b in s {
        if b == b'"' {
            out.push(b'"');
        }
        out.push(b);
    }
    out.push(b'"');
}

#[inline]
fn push_int<I: itoa::Integer>(out: &mut Vec<u8>, v: I) {
    let mut b = itoa::Buffer::new();
    out.extend_from_slice(b.format(v).as_bytes());
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn push_2(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds.
pub fn write_iso8601(out: &mut Vec<u8>, secs: u64) {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    push_int(out, y);
    out.push(b'-');
    push_2(out, m);
    out.push(b'-');
    push_2(out, d);
    out.push(b'T');
    let s = secs % 86_400;
    push_2(out, (s / 3600) as u32);
    out.push(b':');
    push_2(out, ((s % 3600) / 60) as u32);
    out.push(b':');
    push_2(out, (s % 60) as u32);
    out.push(b'Z');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{ScanConfig, scan_all};

    #[test]
    fn iso8601() {
        let mut out = Vec::new();
        write_iso8601(&mut out, 0);
        assert_eq!(out, b"1970-01-01T00:00:00Z");
        out.clear();
        write_iso8601(&mut out, 1_790_000_000);
        assert_eq!(out, b"2026-09-21T14:13:20Z");
        out.clear();
        write_iso8601(&mut out, 951_782_400); // 2000-02-29
        assert_eq!(out, b"2000-02-29T00:00:00Z");
    }

    #[test]
    fn deterministic() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        Generator::new(Profile::Narrow, 7)
            .generate(&mut a, Target::Rows(100), None)
            .unwrap();
        Generator::new(Profile::Narrow, 7)
            .generate(&mut b, Target::Rows(100), None)
            .unwrap();
        assert_eq!(a, b);
        let mut c = Vec::new();
        Generator::new(Profile::Narrow, 8)
            .generate(&mut c, Target::Rows(100), None)
            .unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn every_profile_scans_to_the_requested_rows() {
        for p in Profile::ALL {
            let mut out = Vec::new();
            let stats = Generator::new(p, 1)
                .generate(&mut out, Target::Rows(500), None)
                .unwrap();
            assert_eq!(stats.rows, 500);
            assert_eq!(stats.bytes as usize, out.len());
            let spans = scan_all(
                ScanConfig {
                    delimiter: b',',
                    quote: Some(b'"'),
                    count_fields: true,
                },
                &out,
            );
            assert_eq!(spans.len(), 501, "{p:?}: header + 500 rows");
            let expected = spans[0].fields;
            let mismatches = spans[1..].iter().filter(|s| s.fields != expected).count();
            match p {
                Profile::Ragged => assert!(mismatches > 0),
                _ => assert_eq!(mismatches, 0, "{p:?}"),
            }
        }
    }

    #[test]
    fn byte_target_stops_after_crossing() {
        let mut out = Vec::new();
        let stats = Generator::new(Profile::Narrow, 1)
            .generate(&mut out, Target::Bytes(100_000), None)
            .unwrap();
        assert!(stats.bytes >= 100_000);
        assert!(stats.bytes < 100_000 + (64 << 10));
        assert!(out.ends_with(b"\n"));
    }
}
