# Architecture

## Layers

```
rdt-cli / rdt-ui            presentation
        |
rdt-session                 orchestration (state machine, limits, reconnect)
        |
rdt-ssh    rdt-rdp          protocol clients
        |
rdt-terminal  rdt-config  rdt-secrets  rdt-logging  rdt-platform  rdt-types
```

Dependencies point downwards only.  `rdt-types` has no dependency on any other
RDT crate, which is why it can be unit tested in isolation.

## Threads and async

* The UI runs on the egui/eframe render loop and never blocks.
* One Tokio runtime hosts every session.  Each session owns a task that pumps
  protocol PDUs in both directions.
* UI → session traffic goes through unbounded mpsc channels of small commands;
  session → UI traffic uses a broadcast channel for state changes and a per
  session mpsc for data.
* The framebuffer is behind a mutex held only for the duration of a copy, so a
  slow renderer cannot stall decoding.

## State machine

```
Idle -> Connecting -> Authenticating -> Connected
  ^                                          |
  |                                          v
  +------ Cancelled / Disconnected <- Reconnecting <- Failed
```

Every transition is broadcast to subscribers and written to the audit trail.
Reconnection delay comes from `ReconnectPolicy::delay_for`, which is
deterministic with at most 25 % jitter so tests can assert on it.

## Security boundaries

| Boundary | Mechanism |
| --- | --- |
| SSH host key | `known_hosts` check before any authentication data is sent |
| RDP certificate | rustls validation + pinning / TOFU, decided by `CertPolicy` |
| Secrets at rest | OS keystore or Argon2id + ChaCha20-Poly1305 vault |
| Secrets in memory | `zeroize` on drop, constant-time comparison |
| Secrets in logs | `Redactor` scrubs known keys and registered values |
| Agent control socket | `0700` directory + `SO_PEERCRED` UID check |
| Files | `0600` / `0700` applied at creation, before the first write |

## Error handling

Every fallible path returns `RdtResult<T> = Result<T, RdtError>`; `RdtError`
carries an `ErrorCode` (machine readable), a message (human readable, never
secret) and optional context pairs.  `ErrorCode::is_retryable` drives the
reconnection logic so retry behaviour cannot diverge between SSH and RDP.

## Why these libraries

| Concern | Crate | Reason |
| --- | --- | --- |
| GUI | `eframe`/`egui` 0.36 | immediate mode, renders through OpenGL into our own surface, actively maintained, MIT/Apache-2.0 |
| SSH | `russh` 0.63 | pure Rust, Apache-2.0, used in production by others, exposes a real `Handler` API |
| RDP | `ironrdp-*` 0.17 | Apache-2.0/MIT, embedded rendering (no window handle needed), full PDU support |
| TLS | `rustls` 0.23 + `ring` | no OpenSSL dependency, pure Rust crypto, Mozilla/Apache |
| Terminal | in-tree | full control of the renderer, zero dependencies, fully unit tested |
