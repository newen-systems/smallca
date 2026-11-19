# newen_systems.smallca

Ansible modules that wrap the `smallca` certificate CLI, so a playbook creates, signs and checks certificates with native tasks.

## Requirements

| What | Version |
|---|---|
| ansible-core | 2.16 or later (CI runs 2.21) |
| `smallca` binary | 0.1.1, on the host that runs the module (usually the control node, `delegate_to: localhost`) |
| Python | 3.7 or later on that host |

Install the collection from a pinned tag, and put `smallca` in `PATH` (or set `smallca_path` per task):

```sh
ansible-galaxy collection install 'git+https://github.com/newen-systems/smallca.git#/ansible,v0.1.1'
```

## Modules

Options are the CLI flags in snake_case (`--cert-out` is `cert_out`). Full options, defaults and return values: `ansible-doc newen_systems.smallca.<module>`, and the source in `plugins/modules/`.

| Module | CLI command | Required options | Writes files |
|---|---|---|---|
| `root` | `root create` | `root_dir`, `subject`, `password` | yes |
| `intermediate` | `intermediate create` | root location, `subject`, `cert_out`, `key_out` | yes |
| `intermediate_sign` | `intermediate sign` | root location, `csr`, `cert_out` | yes |
| `leaf` | `leaf create` | `issuer_cert`, `issuer_key`, `subject`, `cert_out`, `key_out` | yes |
| `leaf_sign` | `leaf sign` | `issuer_cert`, `issuer_key`, `csr`, `cert_out` | yes |
| `csr` | `csr create` | `subject`, `key_out`, `csr_out` | yes |
| `bundle` | `certificate bundle` | `certs`, `fullchain_out` | yes |
| `convert` | `certificate convert` | `inputs`, and at least one output option | yes |
| `certificate_info` | `certificate inspect` | `path` or `url` | no |
| `verify` | `certificate verify` | `path` or `url`, and `roots` or `min_remaining` | no |
| `match` | `certificate match` | two or three of `cert`, `key`, `csr` | no |
| `mtls_verify` | `mtls verify` | `client_cert`, `client_trust` | no |

Root location: `root_dir`, or `root_cert` with `root_key` or `root_key_content`. The first two are file paths, the last is the key text, which smallca reads from a pipe.

## Usage

This playbook builds a root, an issuing CA and a server certificate in `./pki`, then verifies the chain. Export `ROOT_PASSWORD` first.

```yaml
- name: Build a small CA and issue a certificate
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    pki_dir: ./pki
    root_password: "{{ lookup('ansible.builtin.env', 'ROOT_PASSWORD') }}"
  tasks:
    - name: Create the root CA
      newen_systems.smallca.root:
        root_dir: "{{ pki_dir }}/root"
        subject: CN=Example Root CA,O=Example
        password: "{{ root_password }}"

    - name: Create the issuing CA
      newen_systems.smallca.intermediate:
        root_dir: "{{ pki_dir }}/root"
        password: "{{ root_password }}"
        subject: CN=Example Issuing CA,O=Example
        cert_out: "{{ pki_dir }}/issuing.crt"
        key_out: "{{ pki_dir }}/issuing.key"

    - name: Issue a server certificate
      newen_systems.smallca.leaf:
        issuer_cert: "{{ pki_dir }}/issuing.crt"
        issuer_key: "{{ pki_dir }}/issuing.key"
        subject: web.example.test
        san: [192.0.2.10]
        cert_out: "{{ pki_dir }}/web.crt"
        key_out: "{{ pki_dir }}/web.key"
        fullchain_out: "{{ pki_dir }}/web-fullchain.pem"

    - name: Check the chain and the time left
      newen_systems.smallca.verify:
        path: "{{ pki_dir }}/web-fullchain.pem"
        roots: "{{ pki_dir }}/root/root.crt"
        host: web.example.test
        min_remaining: 14d
```

```sh
export ROOT_PASSWORD='use a long random password'
ansible-playbook -i localhost, pki.yml
```

## Behaviour

- Idempotent: `changed` comes from smallca, which rewrites nothing when the result would be the same. The second run of the playbook above reports `changed=0`.
- A `leaf` certificate is re-issued when the request changes, the issuer changes, or it is inside its renewal window (30 days, or the last third of a shorter lifetime). Keys are reused until you delete them.
- Check mode runs the writing modules with `--dry-run`: they report `changed` and write nothing. `certificate_info`, `verify`, `match` and `mtls_verify` are read-only and always run.
- Check mode reads real files. A dry run of the playbook above on an empty `pki_dir` fails at `intermediate`, because the root does not exist yet.
- `password` and `root_key_content` are `no_log`. They reach smallca through a pipe or stdin, never a command line or a file.
- Root and intermediate keys are never replaced. An existing one that does not match the request is an error.

## Errors and exit codes

| smallca exit | Module result |
|---|---|
| 0 | Success. |
| 1, 2 | The task fails with `msg` (smallca's message), `code` (smallca's error code) and `rc`. |
| 3 | `verify`, `match` and `mtls_verify` only: the task fails with the reason. With `fail_on_invalid: false` (`fail_on_mismatch: false` for `match`) it succeeds and you branch on `valid` or `match`. |

## Expected result

Each writing module returns `changed` and the paths it wrote. The certificate-issuing modules (`root`, `intermediate`, `intermediate_sign`, `leaf`, `leaf_sign`) also return `subject`, `serial`, `fingerprint_sha256` and `not_after`. Check any certificate with the `verify` task above, or `smallca certificate verify --roots pki/root/root.crt --cert pki/web-fullchain.pem`.

## More

- CLI flags and defaults: `../docs/reference/cli.md`.
- How-to guides: `../docs/howto/` (FreeIPA external CA, mTLS, rotation, root key in a secret manager, cert-manager).
- Module source is generated from `../scripts/ansible-modules.yml` by `../scripts/gen-ansible-modules.py`. Change the spec, not the module files.

Licensed under the Apache License 2.0.
