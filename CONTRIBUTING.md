# Contributing

Thanks for looking at gridsift. It is a small project with a narrow promise
— never modify the evidence, never touch the network, record what was
derived — and contributions are judged against that promise first.

## Ground rules

- **No network code.** Nothing in any crate may open a socket, resolve a
  name or fetch a URL. Enrichment reads local files only.
- **No writes to the source.** Every path the tool writes goes through
  `Source::guard_not_source` before it is created; keep it that way.
- **Approximate results say so.** Lossy counts, estimated cardinalities
  and sampled profiles carry their bounds into the output.
- **Core stays GUI-independent.** `gridsift-core` must not depend on egui
  or on the CLI; the two front ends are shells over it.

## Working on the code

```
cargo build --release
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs the same on Linux, macOS and Windows with the stable toolchain and
a `cargo check` on the minimum supported Rust version (1.88). The scanner
is checked against the `csv` crate on a torture corpus and on random input
(`crates/gridsift-core/tests/differential.rs`); the command-line tool has
end-to-end tests (`crates/gridsift/tests/cli.rs`) that run the real
binary with the index cache redirected into a temporary home.

Synthetic data for manual testing and benchmarks comes from the tool
itself: `gridsift gen --profile narrow --size 1G -o narrow-1g.csv` is
deterministic (seed 1), so numbers can be reproduced by hash. Keep
generated data out of the repository (`bench/data/` is ignored).

## Pull requests

- One change per pull request, with a test where the change has a
  behaviour (the manifest format, a guard, a parser rule).
- Changes to the manifest format bump `MANIFEST_VERSION` only when an
  older reader could misinterpret the new file; additive optional fields
  keep the version.
- Document user-visible behaviour in `docs/` in the same pull request.
- Benchmarks claims need the machine, cache state, build profile and
  commit next to the number (`bench/README.md` shows the format).

By contributing you agree that your contributions are licensed under the
project's terms (MIT OR Apache-2.0).
