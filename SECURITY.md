# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security**
tab and choose **Report a vulnerability**. Do not open a public issue.

Include the smallca version (`smallca version`), the command line with secrets removed,
and what you expected. You get an acknowledgement within 7 days. Fixes for confirmed
issues ship in a patch release with a GitHub security advisory.

Supported versions: the latest release only.

## Threat model

smallca is an offline, file-based CA. It runs as the invoking user and keeps no state
beyond the files you name. It opens a network connection only when given
`--url` (`certificate inspect`, `certificate verify`, `mtls verify`). Those paths
never sign and never read a CA key; `mtls verify --url` presents the client
certificate and key you name, as the client would.

**It protects against:**

- **Disclosure of the root key at rest.** The root key is PKCS#8, encrypted with your
  password (PBES2: PBKDF2-HMAC-SHA256 with 600,000 iterations and AES-256-CBC, via
  `go.step.sm/crypto/pemutil`).
- **A CSR choosing its own profile.** `intermediate sign` copies only the subject and
  public key. Path length, key usage and name constraints come from your flags. CSRs
  with an invalid signature, weak keys (RSA under 2048 bits, curves other than P-256
  and P-384), unknown critical extensions, or trailing data are rejected.
- **Silent replacement of trusted material.** CA keys are never overwritten. A changed
  root subject or a mismatched intermediate is an error, not a re-issue.
- **A root key on the signing host's disk.** `--root-key` reads a pipe, so the key can
  stay in a secret manager and exist only in memory for one command. The buffer is
  zeroed after use (best effort).
- **Torn writes.** Every file is written to a temporary file, synced and renamed.
- **Password exposure on the command line.** The password is read only from a file,
  stdin or an inherited fd, never from a flag value or a prompt, and the buffer is
  zeroed after use (best effort: the Go runtime may keep copies).

**It does not protect against:**

- **A compromised host.** Anyone who can read the root key file and the password, or
  the memory of a running smallca, can sign. Keep the root directory on a machine and
  account you trust, and the password in a secret manager.
- **Clear intermediate and leaf keys.** These are written unencrypted (mode 0600)
  because their consumers need them in clear. Protect them with file permissions,
  encryption at rest or your secret manager.
- **Revocation.** smallca publishes no CRL or OCSP. Limit exposure with short leaf
  lifetimes and `--permitted-dns` name constraints.
- **Weak passwords.** Any non-empty password up to 4096 bytes is accepted. Use a long
  random one.

## Key handling summary

| File | Format | Mode | Encrypted |
|---|---|---|---|
| `root.key` | PKCS#8 PEM | 0600 | yes, with your password |
| intermediate key (`--key-out`) | PKCS#8 PEM | 0600 | no |
| `--k8s-secret-out` manifest | YAML with base64 key | 0600 | no |
| leaf key (`--key-out`) | PKCS#8 PEM | 0600 | no |
| certificates and chains | PEM | 0644 | n/a |

Directories smallca creates get mode 0700.
