# Mutual TLS

In mutual TLS both sides present a certificate. The server proves its name to the
client, and the client proves its identity to the server. smallca issues both
certificates and checks that the two sides will accept each other.

## 1. Issue the certificates

One intermediate can issue both. `--purpose` decides what each certificate is for:

```sh
# Server: accepts connections as api.example.test
smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key \
  --subject api.example.test --purpose server \
  --cert-out api.crt --key-out api.key --fullchain-out api-fullchain.pem

# Client: connects as "backup-agent"
smallca leaf create --issuer-cert issuing.crt --issuer-key issuing.key \
  --subject "CN=backup-agent,O=Example" --san backup-agent.example.test --purpose client \
  --cert-out agent.crt --key-out agent.key --fullchain-out agent-fullchain.pem
```

| `--purpose` | Extended key usage | Use for |
|---|---|---|
| `server` (default) | serverAuth | anything that accepts TLS connections |
| `client` | clientAuth | anything that connects and must prove who it is |
| `both` | serverAuth and clientAuth | peers that do both, such as cluster members |

## 2. Configure each side's trust

- The **server** trusts client certificates with a CA bundle, for example nginx
  `ssl_client_certificate`, Kafka `ssl.truststore`, Envoy `validation_context`. Give it
  the root (`ca/root.crt`), or the intermediate if only this intermediate's clients
  may connect.
- The **client** trusts the server with its own CA bundle, usually the root.
- Each side sends its full chain (`*-fullchain.pem`) so the other side can build the
  path to the root.

## 3. Check before you deploy

```sh
smallca mtls verify \
  --server-cert api-fullchain.pem --server-key api.key --server-trust ca/root.crt \
  --client-cert agent-fullchain.pem --client-key agent.key --client-trust ca/root.crt \
  --host api.example.test
```

Every check is listed with the reason when it fails:

```json
{"schema_version":1,"valid":true,"checks":[
 {"check":"client trusts server certificate","ok":true,"detail":"CN=api.example.test -> CN=Example Issuing CA -> CN=Example Root CA"},
 {"check":"server trusts client certificate","ok":true,"detail":"CN=backup-agent,O=Example -> CN=Example Issuing CA -> CN=Example Root CA"},
 {"check":"server key matches its certificate","ok":true},
 {"check":"client key matches its certificate","ok":true}]}
```

Common failures and what they mean:

| Detail | Cause |
|---|---|
| `certificate specifies an incompatible key usage` | The certificate was issued with the wrong `--purpose`. |
| `certificate signed by unknown authority` | The trust bundle does not hold the issuing root, or the peer's chain is missing an intermediate. |
| `certificate is valid for ..., not ...` | `--host` is not in the server certificate's SANs. |
| `not authorized to sign for this name` | A name is outside the intermediate's `--permitted-dns`. |

## 4. Check the running server

```sh
smallca mtls verify --url api.example.test:8443 \
  --client-cert agent-fullchain.pem --client-key agent.key --client-trust ca/root.crt
```

smallca connects as the client, checks the server certificate, and reports whether
the server accepted the client certificate. Exit code 0 means every check passed, 3
means one failed.
