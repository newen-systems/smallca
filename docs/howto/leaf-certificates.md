# Leaf certificates

`smallca leaf create` issues server and client certificates from an intermediate whose key
smallca can read. It refuses to issue straight from a self-signed root: create an
intermediate first (see `cert-manager-ca-issuer.md` or the README quickstart).

## Server certificate

```sh
smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key \
  --subject web.example.test \
  --san web.example.test --san www.example.test --san 192.0.2.10 \
  --cert-out web.crt --key-out web.key --fullchain-out web-fullchain.pem
```

- `--subject` takes a DN (`"CN=web.example.test,O=Example"`) or a bare common name.
- Each `--san` that parses as an IP address becomes an IP SAN; anything else is a DNS
  SAN. Commas also separate values: `--san a.example.test,b.example.test`.
- A common name that is a dotted host name is always the first DNS SAN, so `--subject`
  alone is enough for a single-name certificate. Other common names are not added.
- Serve `web-fullchain.pem` (the leaf then the intermediate) and `web.key`. Clients trust
  the root. `--chain-out` writes the intermediate alone, for servers that take the
  chain as a separate file.

## Client certificate (mTLS)

```sh
smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key \
  --subject "CN=backup-agent,O=Example" --purpose client --not-after 30d \
  --cert-out agent.crt --key-out agent.key
```

`--purpose client` gives the clientAuth extended key usage only; `--purpose both` gives
serverAuth and clientAuth, for mTLS peers that both accept and make connections. Check
that two sides will accept each other with `smallca mtls verify` (see `mtls.md`).

## Key type and validity

The default key is EC P-256. Use `--crv P-384`, or `--kty RSA --size 2048|3072|4096` for
clients that need RSA. The default validity is 90 days; `--not-after` takes a duration
(`30d`, `2160h`) or an RFC 3339 time and is capped at the intermediate's expiry.

## Re-running

Run the same command from cron or a playbook as often as you like. It keeps the key,
keeps the certificate while it matches the request and is outside its renewal window (30 days, or the last third of a shorter lifetime), and
re-issues it otherwise. Use `--quiet` in cron and rely on the exit code. Renewal and key
rotation are in `rotation.md`.
