# newen_systems.smallca

Ansible modules for smallca, so playbooks issue, sign and check certificates with
native tasks and values from host or group vars.

```sh
ansible-galaxy collection install newen_systems.smallca
```

## Requirements

- ansible-core 2.16 or later.
- The `smallca` binary of the same version on the host that runs the module, usually
  the control node (`delegate_to: localhost`). Set `smallca_path` if it is not in `PATH`.

## Modules

| Module | smallca command | Changes files |
|---|---|---|
| `root` | `root create` | yes |
| `intermediate_sign` | `intermediate sign` | yes |
| `intermediate` | `intermediate create` | yes |
| `leaf` | `leaf create` | yes |
| `leaf_sign` | `leaf sign` | yes |
| `csr` | `csr create` | yes |
| `bundle` | `certificate bundle` | yes |
| `convert` | `certificate convert` | yes |
| `certificate_info` | `certificate inspect` | no |
| `verify` | `certificate verify` | no |
| `match` | `certificate match` | no |
| `mtls_verify` | `mtls verify` | no |

Options are the command's flags in snake_case (`--cert-out` is `cert_out`).
`ansible-doc newen_systems.smallca.<module>` shows each one.

## Behaviour

- Every module is idempotent: `changed` comes from smallca, which rewrites nothing when
  the result would be the same.
- Check mode runs smallca with `--dry-run`: it reports what would change and writes
  nothing.
- Passwords and `root_key_content` are `no_log`, reach smallca through a pipe or stdin,
  and never appear on a command line or on disk.
- `verify`, `match` and `mtls_verify` fail the task when the check fails; set
  `fail_on_invalid: false` (or `fail_on_mismatch: false`) to branch on the result instead.

## Example

```yaml
- name: Certificates for every web host from group vars
  hosts: web
  tasks:
    - name: Issue the server certificate
      newen_systems.smallca.leaf:
        issuer_cert: "{{ pki_dir }}/issuing.crt"
        issuer_key: "{{ pki_dir }}/issuing.key"
        subject: "{{ inventory_hostname }}"
        san: "{{ tls_extra_names | default([]) }}"
        cert_out: "{{ pki_dir }}/hosts/{{ inventory_hostname }}.crt"
        key_out: "{{ pki_dir }}/hosts/{{ inventory_hostname }}.key"
        fullchain_out: "{{ pki_dir }}/hosts/{{ inventory_hostname }}-fullchain.pem"
      delegate_to: localhost

    - name: Fail early if it would not be trusted
      newen_systems.smallca.verify:
        path: "{{ pki_dir }}/hosts/{{ inventory_hostname }}-fullchain.pem"
        roots: "{{ pki_dir }}/root.crt"
        host: "{{ inventory_hostname }}"
        min_remaining: 14d
      delegate_to: localhost
```
