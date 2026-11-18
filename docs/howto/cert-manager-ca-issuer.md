# cert-manager CA Issuer

cert-manager's CA Issuer signs certificates with a CA key it reads from a
`kubernetes.io/tls` Secret. smallca creates that intermediate and the Secret manifest.

## 1. Create the intermediate

```sh
smallca intermediate create --root-dir ca --subject "CN=Example Kubernetes Issuing CA,O=Example" \
  --cert-out k8s/issuing.crt --key-out k8s/issuing.key --fullchain-out k8s/issuing-fullchain.pem \
  --permitted-dns example.test --not-after 5y \
  --k8s-secret-out k8s/issuing-secret.yaml --k8s-secret-name example-issuing-ca \
  --k8s-secret-namespace cert-manager --password-file root.pass
```

`issuing-secret.yaml` holds `tls.crt` (the intermediate), `tls.key` (its key, in clear)
and `ca.crt` (the root). It is written with mode 0600. Do not commit it or print it.
If you store manifests in git, encrypt it first (for example with SOPS or
Sealed Secrets) or create the Secret from `issuing.crt` and `issuing.key` directly.

`--permitted-dns` limits the intermediate to names under `example.test`. A certificate
it issues for any other name fails verification everywhere, even if cert-manager signs
it.

## 2. Apply the Secret and the issuer

```sh
kubectl apply -f k8s/issuing-secret.yaml
```

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: example-ca
spec:
  ca:
    secretName: example-issuing-ca
```

A ClusterIssuer reads its Secret from cert-manager's cluster resource namespace,
`cert-manager` by default. A namespaced `Issuer` reads it from its own namespace.

## 3. Trust the root

Clients need `ca/root.crt` (not the intermediate) in their trust store. Workloads that
call each other can mount it, or use trust-manager to distribute it.

## Ansible

Run the same command through `ansible.builtin.command` with `argv`, pass the password on
`stdin:` with `--password-stdin`, and set
`changed_when: (result.stdout | from_json).changed`. Re-runs keep the existing key and
report `changed: false`.
