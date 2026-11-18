# Verifying chains

```sh
smallca certificate verify --roots ca/root.crt --cert web-fullchain.pem --host www.example.test
```

- `--roots` holds one or more trusted root certificates (PEM bundle, DER or PKCS#7).
- `--cert` holds the certificate to check first. Any further certificates in the same
  file are used as intermediates, so a full chain file works on its own.
- `--chain` adds intermediates from a separate file. Extra copies of the leaf or the
  root are harmless.
- `--host` also checks the certificate is valid for that DNS name.

## Reading the result

```json
{"schema_version":1,"valid":true,"subject":"CN=web.example.test","fingerprint_sha256":"sha256:...",
 "not_after":"2027-02-15T00:00:00Z","chain":["CN=web.example.test","CN=Example Issuing CA","CN=Example Root CA"]}
```

| Exit code | Meaning | stdout |
|---|---|---|
| 0 | the chain verifies | `"valid":true` and the chain, leaf first |
| 3 | it does not | `"valid":false` and the reason in `"error"` |
| 1 | an input could not be read | nothing; the error is on stderr |

In Ansible, `failed_when: verify.rc != 0` fails on both bad chains and unreadable
files, and `verify.rc == 3` tells them apart.

## Common failures

- `x509: certificate signed by unknown authority`: `--roots` does not hold the issuing
  root, or an intermediate is missing; add it with `--chain`.
- `x509: a root or intermediate certificate is not authorized to sign for this name`:
  the leaf is outside an intermediate's `--permitted-dns` constraint.
- `x509: certificate has expired or is not yet valid`: check the clocks, then the
  `not_after` field.

## See what is in the files

```sh
smallca certificate inspect --file web-fullchain.pem
```

Shows each certificate's subject, issuer, validity and days left, key, CA flag and
path length, usages, SANs and name constraints, in file order. It also reads CSRs.

## Cross-check with openssl

```sh
openssl verify -x509_strict -CAfile ca/root.crt -untrusted issuing-fullchain.pem web.crt
```
