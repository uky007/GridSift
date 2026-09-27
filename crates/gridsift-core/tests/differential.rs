//! Differential tests: the scanner + field splitter must agree with the `csv`
//! crate (lenient defaults) on record boundaries, record count and field
//! values, for hand-written torture cases and for randomly generated input.

use std::borrow::Cow;

use gridsift_core::record::split_fields;
use gridsift_core::scan::{ScanConfig, scan_all};
use proptest::prelude::*;

fn reference(data: &[u8]) -> Vec<(u64, Vec<Vec<u8>>)> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(data);
    let mut out = Vec::new();
    for rec in rdr.byte_records() {
        let rec = rec.expect("csv crate accepts any input in flexible mode");
        let pos = rec.position().expect("position").byte();
        out.push((pos, rec.iter().map(|f| f.to_vec()).collect()));
    }
    out
}

fn ours(data: &[u8]) -> Vec<(u64, Vec<Vec<u8>>)> {
    let cfg = ScanConfig {
        delimiter: b',',
        quote: Some(b'"'),
        count_fields: true,
    };
    let mut fields: Vec<Cow<[u8]>> = Vec::new();
    scan_all(cfg, data)
        .into_iter()
        .map(|s| {
            split_fields(
                &data[s.start as usize..s.end as usize],
                b',',
                Some(b'"'),
                &mut fields,
            );
            assert_eq!(
                fields.len() as u32,
                s.fields,
                "scanner field count disagrees with splitter for record at {}",
                s.start
            );
            (s.start, fields.iter().map(|f| f.to_vec()).collect())
        })
        .collect()
}

fn check(data: &[u8]) {
    let want = reference(data);
    let got = ours(data);
    let shown = String::from_utf8_lossy(data);
    assert_eq!(got.len(), want.len(), "record count, input: {shown:?}");
    for ((got_pos, got_fields), (want_pos, want_fields)) in got.iter().zip(&want) {
        assert_eq!(got_fields, want_fields, "fields, input: {shown:?}");
        // The csv crate reports where it *started reading* a record, which
        // includes skipped empty lines; we report the first content byte.
        assert!(
            got_pos >= want_pos,
            "position {got_pos} < csv position {want_pos}, input: {shown:?}"
        );
        assert!(
            data[*want_pos as usize..*got_pos as usize]
                .iter()
                .all(|b| *b == b'\n' || *b == b'\r'),
            "non-terminator bytes skipped before record at {got_pos}, input: {shown:?}"
        );
    }
}

#[test]
fn torture_cases() {
    let cases: &[&[u8]] = &[
        b"",
        b"\n",
        b"\r\n\r\n",
        b"a",
        b"a\n",
        b"a,b\nc,d\n",
        b"a,b\r\nc,d\r\n",
        b"a,b\rc,d\r",
        b"a,b\r\n\r\nc,d",
        b"\n\na,b\n\n\nc,d\n\n",
        b"a,\"b\nc\",d\n",
        b"a,\"b\r\nc\",d\r\n",
        b"\"a\"\"b\",c\n",
        b"\"\"\"\"\n",
        b"\"\",\"\"\n",
        b",\n",
        b",,,\n",
        b"a,\n",
        b",a\n",
        b"\"a\"b,c\n",
        b"\"a\"\"b\"c,d\n",
        b"a\"b,c\n",
        b"a\"b\nc\"\n",
        b"\"unterminated,x\ny",
        b"x,\"unterminated",
        b"\"a\",\"b\"\n\"c\",\"d\"",
        b"a,b\n\"c\n\nd\",e\n",
        b" ,\t\n",
        b"\"\r\"\n",
        b"\"\n\"\n\"\r\n\"\r\n",
        b"a\r\rb\n\n\rc",
    ];
    for c in cases {
        check(c);
    }
}

fn csvish() -> impl Strategy<Value = Vec<u8>> {
    // small alphabet that maximises structural ambiguity
    let alphabet = prop::sample::select(vec![b'a', b'b', b',', b'"', b'\n', b'\r', b' ']);
    prop::collection::vec(alphabet, 0..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]
    #[test]
    fn random_input_matches_csv_crate(data in csvish()) {
        check(&data);
    }
}
