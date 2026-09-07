# Configuration

The configuration lives in one TOML document:

| Platform | Path |
| --- | --- |
| Linux / macOS | `~/.config/rdt/config.toml` |
| Windows | `%APPDATA%\rdt\config.toml` |

Override with `RDT_CONFIG_DIR`, `RDT_DATA_DIR`, `RDT_LOG_DIR` and
`RDT_RUNTIME_DIR` (useful for tests and for running several instances).

```toml
schema_version = 1

[settings.ui]
theme = "dark"                 # system | light | dark
ui_scale_percent = 100
show_status_bar = true
confirm_disconnect = true

[settings.security]
allow_remote_to_local_clipboard = true
allow_local_to_remote_clipboard = true
redact_logs = true
vault_lock_after_minutes = 15

[settings.session]
max_concurrent_sessions = 16
audit_connections = true
audit_retention_days = 90

[settings]
log_level = "info"             # error | warn | info | debug | trace
log_max_mib = 16
log_keep = 5

[[profiles]]
name = "build server"
group = "prod"
protocol = "ssh"

[profiles.endpoint]
host = "build.example.com"
port = 22

[profiles.auth]
method = "password"
source = "prompt"              # prompt | stored

[profiles.ssh]
keepalive_secs = 30
connect_timeout_secs = 15
host_key_policy = "strict"     # strict | accept_new

[profiles.rdp]
cert_policy = "verify_or_pinned"
dynamic_resize = true
```

## Files RDT owns

| File | Purpose | Permissions |
| --- | --- | --- |
| `config.toml` | settings and profiles | 0600 |
| `secrets.vault` | encrypted secret vault | 0600 |
| `known_hosts` | SSH host keys | 0600 |
| `pins.json` | pinned RDP certificates | 0600 |
| `logs/rdt.log` | rotating application log | 0600 |
| `logs/audit.jsonl` | append-only audit trail | 0600 |

Writes are atomic: write a temporary file, `fsync`, apply permissions, rename.
A crash mid-save cannot corrupt the store.
