# Changelog

All notable changes to smallca are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may break the CLI.

## [Unreleased]

## [0.1.0] - 2026-11-18

First public release.

### Added

- `root create`, `intermediate sign`, `intermediate create`, `leaf create` and
  `certificate verify`, with idempotent re-runs and one JSON object per run.
- Key selection with `--kty EC|RSA`, `--crv P-256|P-384` and `--size 2048|3072|4096`.
- `--not-after` accepts a duration with `d` and `y` suffixes or an RFC 3339 time.
- Password from `--password-file`, `--password-stdin` or `--password-fd`.
- `leaf sign` signs CSRs generated elsewhere; `csr create` makes a key and CSR for
  another CA.
- `certificate match` and `certificate bundle` replace
  the common openssl one-liners.
- `certificate verify --min-remaining` fails on certificates that expire too soon, and
  `--url` checks a live server.
- `--purpose server|client|both` on leaf commands, and `mtls verify` to check that a
  server and a client trust each other, offline or against a live server.
- `certificate inspect` shows certificates, chains and CSRs as text or `--json`, from a
  file, stdin, or a live TLS server with `--url`.
- `--root-cert` and `--root-key` on the signing commands read the root from any path,
  including a pipe from a secret manager, instead of `--root-dir`.
- Certificates renew 30 days before expiry, or in the last third of their lifetime if
  that is shorter.
- A subject common name that is a dotted host name is always included as a DNS SAN.
- `--dry-run` on every command: report what would change without writing.
- Ansible collection `newen_systems.smallca` with a module per command, check mode
  and secrets passed through pipes.
- `--quiet` on every command, and exit code 3 when a chain does not verify.
- `intermediate create --k8s-secret-out` writes a `kubernetes.io/tls` Secret for a
  cert-manager CA Issuer.
- `certificate convert` reads PEM, DER, PKCS#7 and PKCS#12 and writes any of them: the
  end certificate, its issuers, the full chain, the private key, one file per certificate,
  a PKCS#12 file or a Java trust store.
- Man-page style `--help` for every command; `docs/reference/cli.md` is generated from it.

[Unreleased]: https://github.com/newen-systems/smallca/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/newen-systems/smallca/releases/tag/v0.1.0
