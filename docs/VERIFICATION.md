# Verification status

## Verified in the development sandbox

`rdt-types`, `rdt-terminal` and `rdt-platform` were compiled and tested with a
real `cargo test` run:

| Crate | Unit tests | Result |
| --- | --- | --- |
| `rdt-types` | 39 | ok |
| `rdt-terminal` | 59 (+1 doc-test) | ok |
| `rdt-platform` | 20 | ok |

`cargo fmt` and `cargo clippy --all-targets` are clean for those three crates.
The tests exercise real behaviour: VT parsing (CSI/OSC/DCS, UTF-8 recovery,
scroll regions, alternate screen), redaction of `password=`/`Authorization:`
pairs, known-host style matching, constant-time secret comparison, zeroization,
OS entropy, path detection and dependency probing.

## Not verified in the sandbox

`rdt-config`, `rdt-secrets`, `rdt-logging`, `rdt-ssh`, `rdt-rdp`, `rdt-session`,
`rdt-ui`, `rdt-agent` and `rdt-cli` have **not** been through `rustc`.  The
reason is environmental, not a code choice: crates.io, `codeload.github.com`,
`raw.githubusercontent.com` and `api.github.com` are all unreachable from the
sandbox, so the dependency graph cannot be resolved and no crate outside the 39
that were vendored before the network was cut can be fetched.

Every `.rs` file was checked with `rustfmt --edition 2021`, which parses the
file, so there are no syntax errors — but that is not a type check.

**Expect type errors in those crates on the first CI run.**  They are written
against the real APIs of `russh` 0.63.2, `ironrdp` 0.17 and `windows-service`
0.8.1, whose sources were readable on disk, and against egui 0.36 from
knowledge.  Treat the first CI run as the point where they become verified.

## How to verify on a normal machine

```bash
rustup toolchain install 1.88.0
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

## Vendored dependencies

`vendor/` holds the crate sources fetched before the network was cut, together
with `scripts/offline/vendor.py` (which can rebuild it from GitHub tags or from
the local source cache) and `scripts/offline/patches.json`, which records the one
documented offline patch (relaxing `syn`'s `proc-macro2` floor).  A normal
`cargo build` against crates.io never sees the vendor directory.
