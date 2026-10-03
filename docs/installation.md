# Installation

Rust 1.88 or newer is required (edition 2024; 1.88 is what the dependency
graph needs — the Linux file-dialog backend).

## From crates.io

```
cargo install gridsift --locked    # gridsift-desktop (the application) and gridsift (the command line)
```

`--locked` builds with the dependency versions the release was tested
with. Both binaries go into `~/.cargo/bin`. The engine is published
separately as [`gridsift-core`](https://crates.io/crates/gridsift-core)
for use as a library. Releases are listed in
[CHANGELOG.md](../CHANGELOG.md).

## Build from source

```
git clone https://github.com/uky007/GridSift.git
cd GridSift
cargo build --release
```

`cargo run` starts the desktop application (`cargo run -- file.csv` opens
a file); the command line is `cargo run --bin gridsift -- …`.

This produces two binaries:

| binary | what it is |
|---|---|
| `target/release/gridsift` | the command-line tool |
| `target/release/gridsift-desktop` | the desktop application (egui) |

For a distributable build with fat LTO and a single codegen unit:

```
cargo build --profile dist
```

The binaries are then in `target/dist/`.

## Platform notes

### Linux

The desktop application links against xcb / xkbcommon. On Debian/Ubuntu:

```
sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

File dialogs use the XDG desktop portal (`rfd`), so a portal implementation
(`xdg-desktop-portal-gtk`, `-kde`, …) should be present.

### macOS

No extra dependencies. The index and hash threads are given
`QOS_CLASS_USER_INITIATED` so that macOS schedules them on performance
cores; nothing needs to be configured.

### Windows

No extra dependencies. The desktop binary is built with
`windows_subsystem = "windows"` in release mode, so it does not open a
console window.

## Where gridsift writes

gridsift never writes next to the evidence. The only files it creates on
its own are index sidecars (`*.gsix`) and analysis caches (`*.gsan` with
the column profile and whole-file value counts, `*.gstl` with the
timelines) in the user cache directory:

| platform | cache directory |
|---|---|
| Linux | `$XDG_CACHE_HOME/gridsift/{index,analysis}/` (default `~/.cache/gridsift/`) |
| macOS | `~/Library/Caches/gridsift/{index,analysis}/` |
| Windows | `%LOCALAPPDATA%\gridsift\{index,analysis}\` |

Both are bound to the source's size and modification time (and to its
SHA-256 once known) and are ignored when the file changes. They hold
values derived from the evidence — the profile's example values, the top
values of columns, timeline buckets — so a case that must not leave
traces on the analyst's machine should remove them when it closes.
Versions of edits (`*.gsedit`, old and new cell values in clear) are
offered under the user's data directory (`~/.local/share/gridsift/versions/`,
`~/Library/Application Support/gridsift/versions/`,
`%APPDATA%\gridsift\versions\`) and may be saved anywhere else. `gridsift index --index PATH` writes it
somewhere else instead. Exports and manifests are written only where the
analyst asks for them.

## Network

None. gridsift makes no network connections of any kind — no update
checks, no telemetry, no DNS. Enrichment reads only local files the
analyst imports (an MMDB database, a CSV lookup table) or data compiled
into the binary (the Public Suffix List snapshot).
