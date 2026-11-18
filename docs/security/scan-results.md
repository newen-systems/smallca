# Scan results

Scans run on 2026-11-17 against the v0.1.0 candidate, Go 1.26.11, macOS arm64. CI
repeats go vet, staticcheck, gosec and govulncheck on every pull request.

| Tool | Version | Scope | Result |
|---|---|---|---|
| go vet | go1.26.11 | `./...` | clean |
| staticcheck | 2026.2.2 (v0.8.2) | `./...` | clean |
| gosec | v2.30.0 | `./...`, 7 files, 2,030 lines | 0 issues after fix F3; 4 `#nosec` justified below |
| govulncheck | v1.9.0 | `./...`, call graph | 0 after fixes F1 and F2 |
| trivy fs | Homebrew build | vuln, secret, misconfig, license | 0 vulnerabilities after F2; licences below |
| gitleaks | Homebrew build | full git history and working tree | no leaks |
| semgrep | 1.185.0 | `p/golang`, `p/secrets`, 32 files | 0 findings |
| go test -fuzz | go1.26.11 | 6 targets, 2 to 3 minutes each | 1 finding, fixed (F4) |

## Findings

**F1. Go standard library: GO-2026-6809 (crypto/x509) and GO-2026-5972 (encoding/asn1).**
Reachable: `certificate verify` calls `x509.Certificate.Verify`, and CSR parsing calls
`asn1.Unmarshal`. Fixed by requiring Go 1.26.11 in `go.mod`; release binaries are built
with it.

**F2. golang.org/x/crypto: GO-2026-5932 (openpgp package unmaintained).** Not
reachable: smallca never imports `openpgp`; the module is pulled in by
`go.step.sm/crypto/pemutil`. Fixed anyway by upgrading to v0.59.0, together with
`go.step.sm/crypto` v0.85.0 to v0.92.0.

**F3. gosec G104 (three unhandled `Close` errors) in `writeIfChanged`.** These are on
error paths that already return the write error. The `Close` result is now discarded
explicitly with a comment.

**F4. Fuzzing: `certfmt.DecodeCSR` accepted an empty PEM block** and returned empty DER
without error. Not exploitable: `x509.ParseCertificateRequest` rejected the empty input
next. Fixed in both `DecodeCSR` and `DecodeCerts`; the input is kept as a regression
case in `internal/certfmt/testdata/fuzz/FuzzDecodeCSR/`.

**F5. Overflowing durations.** Found in review while writing the fuzz target:
`--not-after 300y` overflowed `time.Duration`. Now rejected as too long, with a test.

**F6. Renewal window longer than short lifetimes.** Found in design review: a
certificate issued for 30 days or less was always inside the fixed 30-day renewal
window, so every run re-issued it and idempotency was lost. The window is now 30 days
or the last third of the lifetime, whichever is shorter, with a test.

**F7. semgrep `missing-ssl-minversion`** on the `certificate inspect --url` client. Go
already defaults to TLS 1.2; `MinVersion` is now set explicitly.

## Accepted, with reasons

| Item | Where | Reason |
|---|---|---|
| gosec G304 (file path from variable) | `readCerts`, `readKey`, `writeIfChanged`, `passphrase.FromFile` | Reading the files the operator names is the tool's job. Marked `#nosec G304` with that reason. |
| gosec G402 (`InsecureSkipVerify`) | `FetchChain` for `certificate inspect --url` | Inspect shows whatever chain a server presents, including untrusted ones; that is its purpose. It sends nothing and signs nothing. Trust is judged by `certificate verify`. Marked `#nosec G402`. |
| trivy licence notices | go.step.sm/crypto (Apache-2.0), golang.org/x/crypto and x/sys, filippo.io/edwards25519 (BSD-3-Clause), github.com/pkg/errors (BSD-2-Clause) | All permissive and compatible with Apache-2.0. `NOTICE` credits the Apache-2.0 dependency. |

## Fuzzing

| Target | Package | Executions in 3 min | Result |
|---|---|---|---|
| FuzzDecodeCerts | certfmt | 131 million (after F4) | pass |
| FuzzDecodeCSR | certfmt | 130 million (after F4) | pass; F4 found before the fix |
| FuzzParseCSR | csrutil | 62 million | pass |
| FuzzParseDN | dn | 138 million | pass |
| FuzzParseNotAfter | smallca | 77 million | pass |
| FuzzInspect | smallca | 43 million in 2 min | pass |

Run one again with, for example:

```sh
go test ./internal/csrutil -run '^$' -fuzz '^FuzzParseCSR$' -fuzztime 3m
```
