//! Small process-level probes used for benchmark reporting.

/// Peak resident set size of this process in bytes (0 where unsupported).
#[cfg(unix)]
pub fn peak_rss_bytes() -> u64 {
    // SAFETY: rusage is plain data; getrusage only writes into it.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    if rc != 0 {
        return 0;
    }
    let v = ru.ru_maxrss as u64;
    // macOS reports bytes, Linux and the BSDs report kilobytes.
    if cfg!(target_os = "macos") {
        v
    } else {
        v * 1024
    }
}

#[cfg(not(unix))]
pub fn peak_rss_bytes() -> u64 {
    0
}

/// Ask the OS to schedule the current thread like user-initiated work.
///
/// On macOS, threads spawned by a GUI process default to a QoS class that the
/// scheduler happily parks on efficiency cores; an index build there ran
/// ~3x slower than the same code in a CLI process. No-op elsewhere.
pub fn boost_current_thread() {
    #[cfg(target_os = "macos")]
    // SAFETY: plain FFI call with constant arguments; failure is harmless.
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
    }
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    iso8601_utc(secs)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601_utc(secs: u64) -> String {
    let mut out = Vec::with_capacity(20);
    crate::synth::write_iso8601(&mut out, secs);
    String::from_utf8(out).expect("ascii")
}

/// `1234567` -> `1,234,567`.
pub fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Binary-unit size string (`1.50 GiB`).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouping() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(1234567), "1,234,567");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(10 << 30), "10.00 GiB");
    }

    #[test]
    fn rss_is_positive_on_unix() {
        if cfg!(unix) {
            assert!(peak_rss_bytes() > 0);
        }
    }
}
