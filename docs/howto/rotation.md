# Rotation and renewal

smallca renews by re-running the same command. What happens depends on the tier.

| Tier | Renewal | Key rotation |
|---|---|---|
| Leaf | Automatic: the certificate is re-issued in its renewal window (30 days before expiry, or the last third of its lifetime if shorter). | Delete the key file and re-run. |
| Intermediate (smallca-generated) | Manual: move the old files aside and re-run. | Same; a new key is generated. |
| Intermediate (signed CSR) | Re-run with a new CSR from the subordinate. | The subordinate generates the key. |
| Root | Create a new root in a new directory. | Same. |

## Leaves

Schedule the same `smallca leaf create` command daily, for example with cron or a
systemd timer, and reload the service when it reports `"changed":true`:

```sh
out=$(smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key --subject web.example.test \
  --cert-out /etc/web/tls.crt --key-out /etc/web/tls.key --fullchain-out /etc/web/fullchain.pem) &&
  printf '%s' "$out" | grep -q '"changed":true' && systemctl reload web
```

To rotate the key, delete `/etc/web/tls.key` before the run.

## Intermediates created by smallca

smallca never replaces an intermediate key on its own, because relying parties may pin
it. An intermediate inside its renewal window makes `intermediate create` fail with
"is inside its renewal window; move it aside to re-issue". Before then:

1. Move the old `--cert-out`, `--key-out` and `--fullchain-out` files aside.
2. Re-run the same `intermediate create` command.
3. Deploy the new Secret or files. Leaves issued by the old intermediate stay valid
   until they expire, because they chain to the same root.

## FreeIPA realm CA

FreeIPA renews its externally signed CA with `ipa-cacert-manage`:

```sh
ipa-cacert-manage renew --external-ca          # writes /var/lib/ipa/ca.csr
smallca intermediate sign --root-dir ca --csr ca.csr --cert-out ipa.crt --chain-out ipa-chain.pem \
  --password-file root.pass
ipa-cacert-manage renew --external-cert-file=ipa.crt --external-cert-file=ipa-chain.pem
ipa-certupdate                                  # on every server and client
```

Copy `/var/lib/ipa/ca.csr` to the machine that holds the root, and the two output files
back. The new CSR has a new key, so smallca signs a new certificate.

## Root

The root never renews in place. To replace it:

1. `smallca root create --root-dir ca-2027 ...` with a new subject.
2. Distribute `ca-2027/root.crt` to every trust store while the old root is still
   trusted.
3. Re-sign intermediates under the new root, then roll out leaves.
4. Remove the old root from trust stores once nothing chains to it.

The default root lifetime is 20 years; `--not-after` sets another.
