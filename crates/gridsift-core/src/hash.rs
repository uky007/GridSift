//! Streaming digests of the source. SHA-256 is the canonical forensic identity
//! (NIST-approved SHA-2); BLAKE3 is offered as a fast secondary digest.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use crate::source::Source;

/// Which digests to compute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashSelection {
    pub sha256: bool,
    pub blake3: bool,
}

impl HashSelection {
    pub const NONE: HashSelection = HashSelection {
        sha256: false,
        blake3: false,
    };
    pub const SHA256: HashSelection = HashSelection {
        sha256: true,
        blake3: false,
    };
    pub const ALL: HashSelection = HashSelection {
        sha256: true,
        blake3: true,
    };

    pub fn is_empty(&self) -> bool {
        !self.sha256 && !self.blake3
    }
}

/// Computed digests; `None` where not requested.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Digests {
    pub sha256: Option<[u8; 32]>,
    pub blake3: Option<[u8; 32]>,
}

impl Digests {
    pub fn is_empty(&self) -> bool {
        self.sha256.is_none() && self.blake3.is_none()
    }
}

/// Incremental hasher over a byte stream for the selected algorithms.
pub struct MultiHasher {
    sha: Option<Sha256>,
    b3: Option<blake3::Hasher>,
}

impl MultiHasher {
    pub fn new(sel: HashSelection) -> MultiHasher {
        MultiHasher {
            sha: sel.sha256.then(Sha256::new),
            b3: sel.blake3.then(blake3::Hasher::new),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sha.is_none() && self.b3.is_none()
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        if let Some(h) = &mut self.sha {
            h.update(data);
        }
        if let Some(h) = &mut self.b3 {
            h.update(data);
        }
    }

    pub fn finalize(self) -> Digests {
        Digests {
            sha256: self.sha.map(|h| h.finalize().into()),
            blake3: self.b3.map(|h| *h.finalize().as_bytes()),
        }
    }
}

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse lowercase/uppercase hex into a 32-byte digest.
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

impl fmt::Display for Digests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        if let Some(d) = &self.sha256 {
            write!(f, "sha256:{}", hex(d))?;
            first = false;
        }
        if let Some(d) = &self.blake3 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "blake3:{}", hex(d))?;
        }
        Ok(())
    }
}

/// Standalone full pass over the source. Returns `None` if cancelled.
pub fn hash_source(
    source: &Source,
    sel: HashSelection,
    chunk_size: usize,
    cancel: Option<&AtomicBool>,
) -> io::Result<Option<Digests>> {
    let mut hasher = MultiHasher::new(sel);
    let mut buf = vec![0u8; chunk_size.max(64 * 1024)];
    let mut off = 0u64;
    let len = source.len();
    while off < len {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Ok(None);
        }
        let n = source.read_at(&mut buf, off)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        off += n as u64;
    }
    Ok(Some(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let mut h = MultiHasher::new(HashSelection::ALL);
        h.update(b"abc");
        let d = h.finalize();
        assert_eq!(
            hex(&d.sha256.unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&d.blake3.unwrap()),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn empty_selection() {
        let h = MultiHasher::new(HashSelection::NONE);
        assert!(h.is_empty());
        assert!(h.finalize().is_empty());
    }

    #[test]
    fn hex_roundtrip() {
        let d = [0xABu8; 32];
        assert_eq!(parse_hex32(&hex(&d)), Some(d));
        assert_eq!(parse_hex32("zz"), None);
    }

    #[test]
    fn display() {
        let d = Digests {
            sha256: Some([0; 32]),
            blake3: None,
        };
        assert!(d.to_string().starts_with("sha256:0000"));
    }
}
