# smallca

A small, non-interactive, idempotent certificate authority in one binary, built to be
called from Ansible, shell or CI.

```sh
smallca intermediate sign --root-dir ./ca --csr ipa.csr --cert-out ipa.crt --chain-out ipa-chain.pem --password-file root.pass
```

## What it does

| Job | Command |
|---|---|
| Create a root CA, key encrypted | `smallca root create` |
| Sign another system's sub-CA CSR (FreeIPA, AD CS) | `smallca intermediate sign` |
| Create an intermediate, optionally as a cert-manager Secret | `smallca intermediate create` |
| Issue a server, client (mTLS) or dual-use certificate | `smallca leaf create --purpose server\|client\|both` |
| Sign a CSR from an appliance or service | `smallca leaf sign` |
| Make a key and CSR for another CA | `smallca csr create` |
| See what is in a certificate, chain, CSR or live server | `smallca certificate inspect` |
| Check a chain and the time left | `smallca certificate verify` |
| Check a certificate, key and CSR belong together | `smallca certificate match` |
| Put certificates into one ordered chain | `smallca certificate bundle` |
| Convert, split or repackage PEM, DER, P7B, PFX (PKCS#12) and Java trust stores | `smallca certificate convert` |
| Check two mTLS peers trust each other, offline or live | `smallca mtls verify` |

For Ansible, the `newen_systems.smallca` collection in `ansible/` wraps every command as a
native module (`newen_systems.smallca.leaf`, `.verify`, `.mtls_verify`, ...), with check
mode and values from host or group vars.

Every command except `certificate inspect` prints one JSON object, and the commands
that write files report `"changed"`; running them again with the same inputs changes
nothing. smallca never prompts, so a playbook can call it inline
and use `changed_when: (result.stdout | from_json).changed`.

## Why another CA

| Tool | Fits when | Differs from smallca |
|---|---|---|
| step CLI / step-ca | You want an online CA with ACME, provisioners and renewal. | step-ca is a server. `step certificate sign` re-signs on every run and has no changed/unchanged result. |
| cfssl | You manage profiles as JSON config and run a signing API. | Config-file driven, not idempotent. |
| openssl | You need any X.509 feature at all. | You assemble the CA profile and the idempotency yourself. |
| jsha/minica, mkcert | You need leaf certificates for development. | Neither signs an external CSR, so neither can sign for FreeIPA. |
| Ansible `community.crypto` | Your work already runs inside Ansible. | It copies the CSR's extensions, so the CSR picks its own CA profile; usable only through a playbook. |
| HashiCorp Vault PKI | You run Vault already. | Needs a running Vault. |

smallca is for the gap between them: a file-based offline root, signing that is safe to
re-run, and a binary you can also run by hand.

## Requirements

- Linux, macOS or Windows on amd64 or arm64.
- Go 1.26 or later only if you build from source.

## Install

Download a release archive for your platform and check it against `checksums.txt`, or:

```sh
go install github.com/newen-systems/smallca/cmd/smallca@v0.1.0
```

## Quickstart

```sh
printf '%s\n' 'use a long random password' > root.pass && chmod 600 root.pass

smallca root create --root-dir ca --subject "CN=Example Root CA,O=Example" --password-file root.pass
smallca intermediate create --root-dir ca --subject "CN=Example Issuing CA" \
  --cert-out issuing.crt --key-out issuing.key --fullchain-out issuing-fullchain.pem --password-file root.pass
smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key --subject web.example.test \
  --san web.example.test --san 192.0.2.10 --cert-out web.crt --key-out web.key --fullchain-out web-fullchain.pem
smallca certificate verify --roots ca/root.crt --cert web-fullchain.pem --host web.example.test
smallca certificate inspect --file web-fullchain.pem
```

Run any line twice: the second run reports `"changed":false`.

## Ansible

```yaml
- name: Server certificate for this host
  newen_systems.smallca.leaf:
    issuer_cert: "{{ pki_dir }}/issuing.crt"
    issuer_key: "{{ pki_dir }}/issuing.key"
    subject: "{{ inventory_hostname }}"
    cert_out: "{{ pki_dir }}/{{ inventory_hostname }}.crt"
    key_out: "{{ pki_dir }}/{{ inventory_hostname }}.key"
  delegate_to: localhost
```

See `ansible/README.md` for every module.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | operation error; one JSON line on stderr names it |
| 2 | usage error |
| 3 | `certificate verify`: the chain does not verify |

## Behaviour

- Root and intermediate keys are never replaced. An existing root is checked and kept;
  an existing intermediate that fails a check is an error.
- A certificate is re-issued when the request changes, the issuer changes, or it is
  inside its renewal window: 30 days before expiry, or the last third of its lifetime
  if that is shorter. Leaf keys are reused until you delete them.
- Every file is written atomically. Keys are mode 0600, certificates 0644.
- Each certificate's expiry is capped at its issuer's.
- The root can stay in a secret manager: `--root-cert` and `--root-key` accept a pipe or
  `<(vault kv get ...)`, so the key never touches disk (`docs/howto/`).
- `--chain-out` is always the issuer chain; `--fullchain-out` is the certificate then its
  issuers.
- smallca opens a network connection only when you pass `--url` (to `certificate inspect`,
  `certificate verify` or `mtls verify`). Issuing and signing never touch the network.

## Out of scope

- Revocation (CRL, OCSP), ACME and any network service.
- Talking to secret managers itself: their own CLIs fetch the key and smallca reads the pipe.
- Hardware keys (PKCS#11, KMS).

## More

- `smallca <command> --help`, also in `docs/reference/cli.md`.
- How-to guides in `docs/howto/`.
- Security model and reporting: `SECURITY.md`.

Licensed under the Apache License 2.0.
