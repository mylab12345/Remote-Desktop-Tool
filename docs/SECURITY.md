# Threat model and security design

## Assets

1. Credentials (passwords, private keys, passphrases).
2. Session data in transit and on screen.
3. The configuration and profile store.
4. The local machine (RDT can execute commands remotely and transfer files).

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Man in the middle on SSH | Strict `known_hosts` verification before any authentication; a changed key is a hard error and the connection is refused |
| Man in the middle on RDP | TLS with chain validation; self-signed certificates must be pinned, and a changed fingerprint is refused |
| Credential theft from disk | Secrets are never written to the configuration file; they live in the OS keystore or the Argon2id/ChaCha20-Poly1305 vault, whose header is AEAD AAD so tampering is detected |
| Credential theft from logs | `Redactor` scrubs `password=`, `token=`, `Authorization:` style pairs and every registered secret value before a line reaches a file |
| Credential theft from memory | `Secret`/`SecretBytes` zeroize on drop; comparisons are constant time and length independent |
| Local attacker on a shared machine | Configuration, vault, known hosts, logs and the agent socket are created with owner-only permissions; the agent verifies peer UID |
| Clipboard exfiltration | Both clipboard directions can be disabled independently in Settings |
| Unattended access abuse | The agent only accepts a small JSON command set over a peer-verified local socket; it never exposes a network listener |
| Crash leaving resources behind | Sessions implement `Drop` to close the channel and disconnect; transfers write to a temporary name and only rename on success |
| Replay of an old known_hosts entry | `@revoked` lines are honoured; negated patterns exclude hosts |

## What is explicitly *not* done

* No "accept any certificate" or "accept any host key" mode exists.
* No password is ever logged, even at trace level.
* No telemetry: the application makes no network call except to the host the user
  asked it to connect to.

## Reporting a vulnerability

Open a private security advisory on the repository.  Please include the version
(`rdt version`) and the platform (`rdt doctor`).
