# Converting certificate formats

`smallca certificate convert` reads certificates and a private key in any common
form and writes the forms you name. Name the inputs with `--in` (repeat it) and
pick outputs by flag. Each output's format comes from its file extension, or from
`--format pem|der|p7b`.

| Extension | Format |
|---|---|
| `.der`, `.cer` | DER, one certificate |
| `.p7b`, `.p7c` | PKCS#7 |
| anything else | PEM |

## Split a PFX into PEM files

```sh
smallca certificate convert --in web.pfx --password-file pfx.pass \
  --cert-out web.crt --key-out web.key --chain-out chain.pem
```

The certificate the key matches is the end certificate, and `--chain-out` holds
its issuers. `--fullchain-out` writes both together.

## Serve each certificate as DER

```sh
smallca certificate convert --in chain.p7b --split-dir certs --format der
```

This writes `certs/1-web.example.test.der`, `certs/2-Example_Issuing_CA.der`, and so on,
in input order.

## Build a PFX from PEM files

```sh
smallca certificate convert --in web.crt --in web.key --in chain.pem \
  --p12-out web.pfx --password-file pfx.pass
```

Add `--legacy` for systems that cannot read AES-256 PKCS#12.

## Other conversions

```sh
# PEM bundle to a PKCS#7 file for Windows
smallca certificate convert --in fullchain.pem --out fullchain.p7b

# PKCS#7 or DER back to PEM
smallca certificate convert --in fullchain.p7b --out fullchain.pem

# A Java trust store of a root bundle
smallca certificate convert --in roots.pem --truststore-out roots.p12 --password-file ts.pass

# Decrypt an encrypted key
smallca certificate convert --in web.crt --in web-encrypted.key --password-file key.pass --key-out web.key
```

One password covers every input and output that needs one. To change a PFX
password, split it with the old password, then build it again with the new one.
