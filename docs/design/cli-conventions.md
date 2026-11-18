# CLI conventions

Status: adopted for v0.1.0. This document records how the smallca command line is
shaped, what it borrows from the smallstep `step` CLI and other CA tools, and where
it differs and why.

## Design goals that constrain the CLI

smallca is called by automation (Ansible, shell, CI), not typed at a prompt. Every
choice below serves four goals:

1. **Non-interactive.** No prompt, ever. Missing input is a usage error.
2. **Idempotent.** Running a command twice with the same inputs changes nothing
   the second time and says so (`"changed": false`).
3. **JSON-first.** Success is one JSON object on stdout. Failure is one JSON line
   on stderr. Exit codes carry the result class.
4. **Familiar.** Where a mainstream tool already has a good name for a concept,
   use that name.

## Survey

### Command structure

| Tool | Shape | Example |
|---|---|---|
| step CLI | noun-verb, positional files | `step certificate create SUBJECT CRT KEY --profile root-ca` |
| step CLI | noun-verb, positional files | `step certificate sign CSR CA_CRT CA_KEY --profile intermediate-ca` |
| step CLI | noun-verb | `step certificate verify CRT --roots ROOT --host NAME` |
| step-ca | noun-verb, server bootstrap | `step ca init --pki --name NAME --password-file FILE` |
| cfssl | verb, JSON config files | `cfssl gencert -initca csr.json \| cfssljson -bare ca` |
| openssl | verb (module), single-dash flags | `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -days 3650` |
| jsha/minica | no subcommands | `minica --domains example.test` |

### Concepts and their flag names

| Concept | step | cfssl | openssl | **smallca** |
|---|---|---|---|---|
| Key type | `--kty EC\|RSA\|OKP` | `key.algo` in JSON | `-newkey ec\|rsa` | `--kty EC\|RSA` |
| Curve | `--crv P-256\|P-384\|...` | `key.size` | `-pkeyopt ec_paramgen_curve:` | `--crv P-256\|P-384` |
| RSA size | `--size 2048` | `key.size` | `-newkey rsa:4096` | `--size 2048\|3072\|4096` |
| Validity end | `--not-after 24h\|RFC3339` | `expiry` in config | `-days N` | `--not-after 90d\|RFC3339` |
| Subject | positional `SUBJECT` (CN) | `CN`, `names` in JSON | `-subj /CN=x/O=y` | `--subject DN` or bare CN |
| SANs | `--san` (repeatable, DNS or IP) | `hosts` in JSON | `-addext subjectAltName=` | `--san` (repeatable, DNS or IP) |
| Issuer cert | `--ca FILE` | `-ca FILE` | `-CA FILE` | `--issuer-cert FILE` |
| Issuer key | `--ca-key FILE` | `-ca-key FILE` | `-CAkey FILE` | `--issuer-key FILE` |
| Path length | `--path-len N` | `max_path_len` in config | `basicConstraints=pathlen:N` | `--path-len N` |
| Password | `--password-file`, `--ca-password-file` | none (keys in clear) | `-passin file:\|fd:\|stdin` | `--password-file`, `--password-stdin`, `--password-fd` |
| Unencrypted key | `--no-password --insecure` | always | `-nodes` / `-noenc` | implied (see below) |
| Overwrite | `--force` | always | always | idempotent (see below) |
| Trust roots | `--roots FILE` | `-ca-bundle` | `-CAfile` | `--roots FILE` |
| Host check | `--host NAME` | n/a | `-verify_hostname` | `--host NAME` |
| Output files | positional `CRT KEY` | `cfssljson -bare PREFIX` | `-out`, `-keyout` | `--cert-out`, `--key-out`, `--chain-out`, `--fullchain-out` |
| JSON output | `--format json` on inspect | always JSON | none | always |

## The standard

### S1. Noun-verb subcommands

```
smallca root create
smallca intermediate sign      # external CSR, for example FreeIPA
smallca intermediate create    # smallca generates the key, for example cert-manager
smallca leaf create            # smallca generates the key
smallca leaf sign              # external CSR, for example an appliance
smallca csr create             # key and CSR for a CA smallca does not run
smallca certificate inspect
smallca certificate verify
smallca certificate match
smallca certificate bundle
smallca certificate convert
smallca mtls verify
smallca version
smallca help [command]
```

Adopted from step. The noun is the tier of the PKI being acted on, which makes the
help listing read as the PKI itself. `intermediate sign` and `intermediate create`
are separate commands rather than one command with a `--csr` switch because their
inputs, outputs and idempotency rules differ.

**Divergence:** step has one `certificate create` with `--profile root-ca|intermediate-ca|leaf`.
smallca splits the tiers into nouns because each tier takes different inputs: the
root lives in a directory with an encrypted key, an intermediate needs the root and
its password, a leaf needs an intermediate's clear key. One command with
profile-dependent required flags would make `--help` and validation conditional.

**Noun rule.** Tier nouns (`root`, `intermediate`, `leaf`) act on your own PKI and
need its keys. Format nouns (`certificate`, `csr`, `mtls`) act on any file or server,
from any CA, and never need a CA key. `create` makes something new with a new key,
`sign` signs a request whose key lives elsewhere, `verify` and `inspect` only read.

### S2. Long flags only, kebab-case, no positional arguments

Every input is a named `--flag VALUE`. Positional arguments are a usage error.

**Divergence:** step takes files positionally (`CRT_FILE KEY_FILE`). Ansible `argv`
lists and shell scripts are easier to read and harder to get wrong when every value
is named, and named flags can be reported together when missing.

### S3. One name per concept

| Concept | Flag | Notes |
|---|---|---|
| Key type | `--kty EC\|RSA` | default EC |
| Curve | `--crv P-256\|P-384` | default P-384 for CAs, P-256 for leaves |
| RSA size | `--size 2048\|3072\|4096` | default 3072 |
| Validity | `--not-after` | duration or RFC 3339 time, capped at the issuer's expiry |
| Subject | `--subject` | RFC 2253 DN, or a bare common name |
| SANs | `--san` | repeatable and comma-separated; IPs detected |
| Root location | `--root-dir` | holds `root.crt` and `root.key` |
| Issuer (leaf) | `--issuer-cert`, `--issuer-key` | the intermediate that signs leaves |
| Usage | `--purpose server\|client\|both` | extended key usage of a leaf |
| Input to read | `--file` (inspect), `--cert`, `--key`, `--csr` | `--cert` is always a certificate |
| Outputs | `--cert-out`, `--key-out`, `--chain-out`, `--fullchain-out`, `--k8s-secret-out` | every written file is named by a `*-out` flag; `--chain-out` is always the issuer chain without the certificate, `--fullchain-out` the certificate then its issuers |
| Name constraints | `--permitted-dns` | repeatable |
| Password | `--password-file`, `--password-stdin`, `--password-fd` | exactly one |

`--kty`, `--crv`, `--size`, `--not-after`, `--san`, `--path-len`,
`--password-file`, `--roots` and `--host` are step's names with step's meaning.

**Divergences:**

- `--kty OKP` (Ed25519) and `--crv P-521` are not offered. FreeIPA and several TLS
  stacks reject Ed25519 CA certificates, and the CSR parser accepts P-256 and P-384
  only. A key type smallca can create but its own sign path refuses would be a trap.
- RSA defaults to 3072 bits, not step's 2048, because these keys sign for years.
- `--not-after` also accepts `d` (days) and `y` (365-day years) suffixes. CA
  lifetimes are written in years; `87600h` is an error waiting to happen.
- `--not-before` is not offered. smallca backdates every certificate by five
  minutes to absorb clock skew, which is the only reason automation sets it.
- Output paths are `--*-out` flags rather than positional files (see S2).

**Divergence: issuer names.** step calls the leaf issuer `--ca` and `--ca-key`.
In smallca "ca" could mean the root or the intermediate, so leaf commands say
`--issuer-cert` and `--issuer-key`, and the root is always `--root-dir`,
`--root-cert` and `--root-key`. Every flag names exactly one thing.

**Divergence: `--purpose`.** step sets usages through templates. smallca has one
flag with three plain values, so an mTLS client certificate is
`--purpose client`, not a template file.

### S4. Passwords: file, stdin or fd, never a prompt

Exactly one of:

- `--password-file FILE` (step's name): the usual choice for scripts.
- `--password-stdin`: for Ansible's `command` module `stdin:` parameter, so the
  password never touches disk or the process list. Same idea as
  `docker login --password-stdin`.
- `--password-fd N`: for callers that pass an inherited pipe.

One trailing newline (LF or CRLF) is trimmed. An empty password, more than 4096
bytes, or two sources at once is an error. The password is never accepted as a flag
value, because that would put it in the process list and shell history.

**Divergence:** step uses `--password-file` for the key being created and
`--ca-password-file` for the issuer's key. smallca has exactly one encrypted key, the
root, so one set of names covers both `root create` (encrypt) and the commands that
sign with the root (decrypt).

**Divergence:** step requires `--no-password --insecure` to write a key in clear.
smallca always encrypts the root key and never encrypts intermediate or leaf keys,
because their consumers (cert-manager, web servers) need them in clear. A flag that
every invocation must pass protects nothing, so the behaviour is fixed and
documented instead.

### S5. Idempotency instead of `--force`

There is no `--force`. step's `--force` means "overwrite without asking"; smallca
never asks. Instead:

- Certificates are re-issued when the request no longer matches what is on disk
  (key, subject, SANs, usages, path length, name constraints), when the issuer
  changed, or once inside the renewal window: 30 days before expiry, or the last
  third of the lifetime if that is shorter, so short-lived certificates stay
  idempotent. Otherwise `changed: false` and no write.
- CA keys are never replaced. An existing root is checked and kept. An existing
  intermediate that fails a check is an error; move it aside to re-issue.
- Leaf keys are reused when present. Delete the key file to rotate it.
- Writes are atomic (temp file, fsync, rename). Keys are mode 0600, certificates 0644.

### S6. Output

- Success: one JSON object on stdout, always including `"schema_version": 1`.
  Mutating commands include `"changed"`.
- `--quiet` on every command suppresses stdout; the exit code still carries the result.
- No `--json` flag on commands that act: JSON is their only format. The one
  exception is `certificate inspect`, whose job is to be read by a person: it
  prints aligned text by default and one JSON object with `--json`, like step's
  `certificate inspect --format json`.
- Errors: one JSON line on stderr:
  `{"schema_version":1,"code":"sign_failed","message":"..."}`.
  Usage errors use `"code":"usage"`.
- `--help` prints a man-page style page (NAME, USAGE, DESCRIPTION, FLAGS,
  EXAMPLES, OUTPUT, EXIT CODES) on stdout and exits 0. The reference in
  `docs/reference/cli.md` is generated from the same text and a test fails when
  they differ.

**Divergence:** step prints human text by default and offers `--format json` on some
commands. smallca's callers parse output, so JSON is the default and only format.

### S7. Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | operation error (unreadable input, wrong password, refused request) |
| 2 | usage error (unknown command or flag, missing or conflicting flags) |
| 3 | `certificate verify` ran and the chain does not verify |

Code 3 lets a caller tell "this certificate is bad" from "I could not check it".
step returns non-zero for both.

### S8. Durations

Go duration syntax (`36h`, `90m`) plus whole-number `d` and `y` suffixes (`90d`,
`10y`), or an RFC 3339 timestamp (`2030-01-01T00:00:00Z`). Values must be positive.
A child's `NotAfter` is always capped at its issuer's.
