# Installation

gridsift is not on crates.io yet; build it from source. Rust 1.85 or newer
(edition 2024) is required.

## Build from source

```
git clone https://github.com/uky007/GridSift.git
cd GridSift
cargo build --release
```

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
its own are index sidecars (`*.gsix`) in the user cache directory:

| platform | index cache |
|---|---|
| Linux | `$XDG_CACHE_HOME/gridsift/index/` (default `~/.cache/gridsift/index/`) |
| macOS | `~/Library/Caches/gridsift/index/` |
| Windows | `%LOCALAPPDATA%\gridsift\index\` |

A sidecar is bound to the source's size and modification time and is
ignored when either changes. `gridsift index --index PATH` writes it
somewhere else instead. Exports and manifests are written only where the
analyst asks for them.

## Network

None. gridsift makes no network connections of any kind — no update
checks, no telemetry, no DNS. Enrichment reads only local files the
analyst imports (an MMDB database, a CSV lookup table) or data compiled
into the binary (the Public Suffix List snapshot).
