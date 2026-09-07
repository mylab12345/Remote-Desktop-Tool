# Remote Desktop Tool (RDT)

A production-grade, cross-platform remote access application written entirely in
Rust.  One binary provides a desktop client and, optionally, a headless
unattended agent/service.

* **SSH** — embedded terminal (in-tree VT100/xterm emulator), SFTP transfers,
  password / private key / SSH-agent authentication, strict host key
  verification, keepalives, timeouts, cancellation, concurrent sessions and
  automatic reconnection.
* **RDP** — a genuinely *embedded* client built on IronRDP: TLS with certificate
  validation and pinning, keyboard and mouse injection, clipboard bridging,
  fullscreen and dynamic resizing, multiple sessions, clean resource release.
* **Platforms** — Windows 10/11, Windows Server, Ubuntu, Debian, Fedora, RHEL,
  Rocky Linux, AlmaLinux.

Everything is rendered inside the application's own window.  No external
terminal emulator or RDP client is ever launched, and no protocol is mocked.

## Layout

```
crates/
  rdt-types      shared domain types, typed errors, secret handling, redaction
  rdt-platform   OS detection, paths, dependency probing, service integration
  rdt-config     TOML settings and profile store (atomic, 0600)
  rdt-secrets    OS keystore + Argon2id/ChaCha20-Poly1305 encrypted vault
  rdt-logging    rotating logs, audit trail (JSONL), secret redaction
  rdt-terminal   VT100/xterm emulator (parser, screen model, input encoding)
  rdt-ssh        russh client: known_hosts, auth, PTY, SFTP
  rdt-rdp        IronRDP session: TLS, framebuffer, input, clipboard
  rdt-session    state machine, concurrency limits, reconnection, cancellation
  rdt-ui         egui/eframe desktop interface (8 pages)
  rdt-agent      headless agent: local control socket, service entry point
  rdt-cli        the `rdt` binary
```

## Build

```bash
scripts/build.sh            # format, lint, test, then a release build
cargo run -p rdt-cli        # the desktop application
cargo test --workspace      # unit and integration tests
```

See [docs/BUILD.md](docs/BUILD.md) for toolchain and packaging details, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Security

* Host keys and certificates are verified before any credential is sent.
* Secrets never appear in configuration files, logs or audit records.
* Key material is wiped from memory (`zeroize`) and stored in the OS keystore or
  an Argon2id-protected vault.
* Configuration, vault, known hosts and log files are created `0600`/`0700`.

Read [docs/SECURITY.md](docs/SECURITY.md) for the threat model and
[docs/CONFIG.md](docs/CONFIG.md) for every setting.

## Verification status

`rdt-types`, `rdt-terminal` and `rdt-platform` are compiled and unit tested
(119 passing tests).  The remaining crates are written but have not been through
`rustc` in the sandbox used for development, because the crate registry is
unreachable there; CI (`.github/workflows/ci.yml`) is the authoritative check.
See [docs/VERIFICATION.md](docs/VERIFICATION.md).
