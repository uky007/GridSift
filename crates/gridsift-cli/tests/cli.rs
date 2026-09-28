//! End-to-end checks of the command-line tool: the promises that matter for
//! evidence handling are exercised through the real binary, with the index
//! cache redirected into a temporary home.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn workdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("gridsift-cli-{}-{n}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `gridsift` with the cache directory inside `home`.
fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gridsift"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("LOCALAPPDATA", home)
        .output()
        .expect("run gridsift")
}

fn ok_json(home: &Path, args: &[&str]) -> serde_json::Value {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "gridsift {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json output")
}

fn fails(home: &Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(
        !out.status.success(),
        "gridsift {args:?} unexpectedly succeeded"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn explicit_parser_settings_win_over_the_cached_index() {
    let dir = workdir();
    let csv = dir.join("t.csv");
    fs::write(&csv, "h1,h2\n1,2\n3,4\n").unwrap();
    // an index built with the sniffed dialect (header) …
    ok_json(&dir, &["index", s(&csv), "--json"]);
    let with_header = ok_json(&dir, &["rows", s(&csv), "--json"]);
    assert_eq!(with_header["records"].as_array().unwrap().len(), 2);
    assert_eq!(with_header["from_index"], true);
    // … must not be applied to a run that says there is no header
    let no_header = ok_json(&dir, &["rows", s(&csv), "--no-header", "--json"]);
    assert_eq!(no_header["records"].as_array().unwrap().len(), 3);
    // and the header run still sees its own index afterwards
    let again = ok_json(&dir, &["rows", s(&csv), "--json"]);
    assert_eq!(again["records"].as_array().unwrap().len(), 2);
    assert_eq!(again["from_index"], true);

    // an explicit --index built with a header is ignored (with a warning)
    // when the settings differ, never silently reused
    let idx = dir.join("explicit.gsix");
    ok_json(&dir, &["index", s(&csv), "--index", s(&idx), "--json"]);
    let out = run(
        &dir,
        &["rows", s(&csv), "--no-header", "--index", s(&idx), "--json"],
    );
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 3);
    assert!(String::from_utf8_lossy(&out.stderr).contains("different parser settings"));
}

#[test]
fn no_write_path_can_reach_the_evidence() {
    let dir = workdir();
    let csv = dir.join("evidence.csv");
    fs::write(&csv, "a,b\n1,2\n").unwrap();
    let before = fs::read(&csv).unwrap();
    // the output itself
    assert!(fails(&dir, &["export", s(&csv), "-o", s(&csv), "-f"]).contains("refusing"));
    // the index sidecar
    assert!(fails(&dir, &["index", s(&csv), "--index", s(&csv)]).contains("refusing"));
    // the manifest: a source named like the manifest of the requested output
    let tricky = dir.join("out.csv.manifest.json");
    fs::write(&tricky, "a,b\n1,2\n").unwrap();
    let e = fails(&dir, &["export", s(&tricky), "-o", s(&dir.join("out.csv"))]);
    assert!(e.contains("refusing"), "{e}");
    assert_eq!(fs::read(&csv).unwrap(), before);
    assert_eq!(fs::read(&tricky).unwrap(), b"a,b\n1,2\n");
    assert!(!dir.join("out.csv").exists());
}

#[test]
fn lookup_join_settings_are_part_of_the_manifest() {
    let dir = workdir();
    let csv = dir.join("src.csv");
    fs::write(&csv, "ip,host\n10.0.0.1,a\n10.0.0.2,b\n").unwrap();
    let lookup = dir.join("lookup.csv");
    fs::write(
        &lookup,
        "primary_ip,alternate_ip,owner\n10.0.0.1,10.0.0.2,alice\n10.0.0.2,10.0.0.1,bob\n",
    )
    .unwrap();
    let mut ops = Vec::new();
    for (key, out) in [("primary_ip", "p.csv"), ("alternate_ip", "a.csv")] {
        let spec = format!("ip={}:{key}:owner", s(&lookup));
        let v = ok_json(
            &dir,
            &[
                "export",
                s(&csv),
                "-o",
                s(&dir.join(out)),
                "--lookup",
                &spec,
                "--json",
            ],
        );
        let rule = &v["operations"][0]["rules"][0];
        assert_eq!(rule["dataset"]["lookup"]["key"], key);
        assert_eq!(
            rule["dataset"]["lookup"]["values"],
            serde_json::json!(["owner"])
        );
        assert_eq!(rule["dataset"]["lookup"]["header"], true);
        ops.push(v["operations"].clone());
    }
    // same table, same value column, different key: different history
    assert_ne!(ops[0], ops[1]);
    assert_ne!(
        fs::read(dir.join("p.csv")).unwrap(),
        fs::read(dir.join("a.csv")).unwrap()
    );
}

#[test]
fn exact_search_selects_whole_fields() {
    let dir = workdir();
    let csv = dir.join("ips.csv");
    fs::write(&csv, "ip,n\n10.0.0.1,x\n10.0.0.10,y\n10.0.0.100,z\n").unwrap();
    let literal = ok_json(&dir, &["search", s(&csv), "10.0.0.1", "-c", "ip", "--json"]);
    assert_eq!(literal["matches"], 3);
    let exact = ok_json(
        &dir,
        &[
            "search",
            s(&csv),
            "10.0.0.1",
            "-c",
            "ip",
            "--exact",
            "--json",
        ],
    );
    assert_eq!(exact["matches"], 1);
    assert_eq!(exact["query"]["kind"], "exact");
    // the count a value list shows is the count the pivot selects
    let freq = ok_json(&dir, &["freq", s(&csv), "-c", "ip", "--json"]);
    assert_eq!(freq["top"][0]["count"], 1);
    let pivot = ok_json(
        &dir,
        &[
            "freq",
            s(&csv),
            "-c",
            "n",
            "-s",
            "10.0.0.1",
            "--exact",
            "--json",
        ],
    );
    assert_eq!(pivot["counted"], 1);
    // --regex and --exact are alternatives
    assert!(
        fails(&dir, &["search", s(&csv), "x", "--regex", "--exact"]).contains("cannot be used")
    );
}

#[test]
fn export_publishes_output_with_manifest_and_verify_states_its_scope() {
    let dir = workdir();
    let csv = dir.join("src.csv");
    fs::write(&csv, "ip,host\n10.0.0.1,a\n10.0.0.2,b\n10.0.0.3,c\n").unwrap();
    let out = dir.join("finding.csv");
    let manifest = dir.join("finding.csv.manifest.json");
    let v = ok_json(
        &dir,
        &["export", s(&csv), "-o", s(&out), "-s", "10.0.0.2", "--json"],
    );
    assert!(out.exists() && manifest.exists());
    assert_eq!(v["records"], 1);
    // the manifest's output digest is the file's digest
    let m: serde_json::Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let h = ok_json(&dir, &["hash", s(&out), "--json"]);
    assert_eq!(m["output"]["sha256"], h["sha256"]);
    assert_eq!(m["operations"][0]["op"], "search");

    // verify: source present → both checked
    let ver = ok_json(&dir, &["verify", s(&out), "--json"]);
    assert_eq!(ver["ok"], true);
    assert_eq!(ver["scope"], "output+source");
    assert_eq!(ver["source_checked"], true);

    // overwrite replaces both files consistently
    let v2 = ok_json(
        &dir,
        &[
            "export",
            s(&csv),
            "-o",
            s(&out),
            "-s",
            "10.0.0",
            "-f",
            "--json",
        ],
    );
    assert_eq!(v2["records"], 3);
    let m2: serde_json::Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(m2["output"]["records"], 3);
    assert_eq!(ok_json(&dir, &["verify", s(&out), "--json"])["ok"], true);
    // no temporaries left behind: source, output, manifest
    assert_eq!(
        fs::read_dir(&dir)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().is_file())
            .count(),
        3
    );

    // source gone: output-only, and --require-source says so
    fs::rename(&csv, dir.join("moved.csv")).unwrap();
    let ver = ok_json(&dir, &["verify", s(&out), "--json"]);
    assert_eq!(ver["ok"], true);
    assert_eq!(ver["scope"], "output-only");
    let out_ = run(&dir, &["verify", s(&out), "--require-source", "--json"]);
    assert!(!out_.status.success());
    let ver: serde_json::Value = serde_json::from_slice(&out_.stdout).unwrap();
    assert_eq!(ver["ok"], false);
    // and with --source pointing at the moved file, everything checks again
    let ver = ok_json(
        &dir,
        &[
            "verify",
            s(&out),
            "--source",
            s(&dir.join("moved.csv")),
            "--require-source",
            "--json",
        ],
    );
    assert_eq!(ver["ok"], true);
    assert_eq!(ver["scope"], "output+source");
}
