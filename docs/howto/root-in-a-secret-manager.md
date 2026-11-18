# Keep the root in a secret manager

The root key does not have to live on disk next to smallca. The signing commands
(`intermediate sign`, `intermediate create`) take `--root-cert` and `--root-key` from any
path, so your secret manager's CLI can hand them over through a pipe:

- `--root-key -` reads the key from standard input.
- `--root-key <(command)` uses shell process substitution: the key passes through a
  pipe (`/dev/fd/N`) and is never written to a file.
- The password, if the key is encrypted, comes from `--password-file`, `--password-stdin`
  or `--password-fd` as usual. A key stored in clear needs no password, and giving one
  for a clear key is an error, so you always know which case you are in.

smallca itself holds no credentials for any secret store. You authenticate with the
store's own tool, and smallca only sees the key for the length of one command.

## 1. Create the root and move it into the store

```sh
smallca root create --root-dir ca --subject "CN=Example Root CA,O=Example" --password-file root.pass
# store ca/root.crt, ca/root.key (encrypted) and root.pass, then delete the local copies
```

Keep the encrypted key and its password in separate secrets, or separate stores, so
one leak is not enough. The certificate is public; keep a copy wherever it is useful.

## 2. Sign with the root fetched on demand

HashiCorp Vault (KV v2):

```sh
smallca intermediate sign --csr ipa.csr --cert-out ipa.crt --chain-out ipa-chain.pem \
  --root-cert ca/root.crt \
  --root-key <(vault kv get -field=key secret/pki/root) \
  --password-file <(vault kv get -field=password secret/pki/root-password)
```

AWS Secrets Manager:

```sh
smallca intermediate create --subject "CN=Example Issuing CA" \
  --cert-out issuing.crt --key-out issuing.key --root-cert ca/root.crt \
  --root-key <(aws secretsmanager get-secret-value --secret-id pki/root-key \
                 --query SecretString --output text) \
  --password-file <(aws secretsmanager get-secret-value --secret-id pki/root-password \
                      --query SecretString --output text)
```

Kubernetes Secret:

```sh
smallca intermediate sign --csr ipa.csr --cert-out ipa.crt --root-cert ca/root.crt \
  --root-key <(kubectl -n pki get secret root-ca -o jsonpath='{.data.tls\.key}' | base64 -d) \
  --password-file <(kubectl -n pki get secret root-ca-password -o jsonpath='{.data.password}' | base64 -d)
```

Any other store works the same way: whatever prints the PEM can feed `--root-key`.

## Ansible

Ansible's `command` module has one `stdin:`, so pass the key there and the password
through a file the play removes, or store the key in clear in the secret manager and
let the manager's encryption and access policy protect it:

```yaml
- name: Sign the CSR with the root from the secret manager
  ansible.builtin.command:
    argv: [smallca, intermediate, sign, --root-cert, "{{ ca_dir }}/root.crt", --root-key, "-",
           --csr, "{{ work }}/ipa.csr", --cert-out, "{{ work }}/ipa.crt",
           --chain-out, "{{ work }}/ipa-chain.pem"]
    stdin: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/pki/root:key') }}"
  delegate_to: localhost
  register: signed
  changed_when: (signed.stdout | from_json).changed
  no_log: true
```

## Limits

- The key is in smallca's memory while it signs. A secret manager protects the key at
  rest and controls who may fetch it; it does not stop a compromised host that is
  allowed to fetch it.
- To keep the key out of the signing host entirely, the key must stay in an HSM or cloud
  KMS that signs on smallca's behalf. smallca does not support that yet.
