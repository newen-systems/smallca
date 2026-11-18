# smallca command reference

Generated from `smallca --help` by `go test ./internal/smallca -run TestReferenceDocs -update`. Do not edit by hand.

## smallca

```text
smallca: non-interactive, idempotent certificate authority for automation

USAGE
  smallca <noun> <verb> [flags]

COMMANDS
  root create           create the root CA in a directory, or check the existing one
  intermediate sign     sign an externally generated subordinate-CA CSR with the root
  intermediate create   generate an intermediate CA key and a root-signed certificate for it
  leaf create           issue a server or client certificate from an intermediate
  leaf sign             sign a server or client CSR generated elsewhere
  csr create            create a key and a certificate signing request for another CA
  certificate inspect   show what is inside a certificate, chain or CSR
  certificate verify    verify a certificate chains to a trusted root and is not about to expire
  certificate match     check that a certificate, key and CSR belong together
  certificate bundle    put certificates from several files into one ordered chain
  certificate convert   convert, split or repackage certificates and keys between PEM, DER, PKCS#7 and PKCS#12
  mtls verify           check that a server and a client certificate trust each other for mutual TLS
  version               print version and commit as JSON
  help [command]        show help

Every command prints one JSON object on stdout ("schema_version":1), except
certificate inspect, which prints text unless given --json. Commands that write
files are idempotent: re-running one with the same inputs returns
"changed":false and rewrites nothing. An error is one JSON line on stderr:
  {"schema_version":1,"code":"...","message":"..."}

Exit codes: 0 ok, 1 error, 2 usage error, 3 certificate verify: not valid.

smallca never prompts. The root key password comes from --password-file,
--password-stdin or --password-fd.

Run 'smallca <command> --help' for a command's flags and examples.
```

## smallca root create

```text
NAME
  smallca root create - create the root CA in a directory, or check the existing one

USAGE
  smallca root create --root-dir DIR --subject DN [flags] (--password-file FILE | --password-stdin | --password-fd N)

DESCRIPTION
  Creates DIR/root.crt and DIR/root.key, a self-signed root CA whose private
  key is stored as PKCS#8 encrypted with the given password. The root profile is
  CA:TRUE (critical) with the given path length, and keyUsage keyCertSign and
  cRLSign (critical).

  If the root already exists, root create decrypts the key, checks it matches the
  certificate and that the subject equals --subject, and reports changed:false.
  It never overwrites an existing root.

FLAGS
  --crv CURVE
      EC curve: P-256 or P-384 (default P-384)
  --dry-run
      report what would change without writing any file
  --kty TYPE
      key type: EC or RSA (default EC)
  --not-after DURATION
      root validity: a duration (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry (default 20y)
  --password-fd FD
      read the root key password from this inherited file descriptor
  --password-file FILE
      read the root key password from this file
  --password-stdin
      read the root key password from stdin
  --path-len N
      root path length constraint (-1 for none) (default 2)
  --quiet
      print nothing on stdout; rely on the exit code
  --root-dir DIR
      directory for root.crt and root.key (created mode 0700)
  --size BITS
      RSA key size in bits: 2048, 3072 or 4096 (default 3072)
  --subject DN
      root subject DN, e.g. "CN=Example Root CA,O=Example"

EXAMPLES
  # Create a root, reading the password from a file
  smallca root create --root-dir ./ca --subject "CN=Example Root CA,O=Example" \
    --password-file ./root.pass

  # Same, from Ansible's command module (stdin: "{{ root_password }}")
  smallca root create --root-dir ./ca --subject "CN=Example Root CA" --password-stdin

OUTPUT
  {"schema_version":1,"changed":true,"root_cert":"ca/root.crt","root_key":"ca/root.key",
   "subject":"CN=Example Root CA,O=Example","serial":"...","fingerprint_sha256":"sha256:...",
   "not_after":"2046-11-17T00:00:00Z"}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca intermediate sign

```text
NAME
  smallca intermediate sign - sign an externally generated subordinate-CA CSR with the root

USAGE
  smallca intermediate sign (--root-dir DIR | --root-cert FILE --root-key FILE) --csr FILE --cert-out FILE [flags]

DESCRIPTION
  Signs a subordinate-CA certificate signing request, for example the
  /root/ipa.csr that ipa-server-install --external-ca writes, with the root in
  --root-dir. The subject is copied byte-for-byte from the CSR, because FreeIPA
  compares the DER. CSR extensions are never copied: the certificate gets
  CA:TRUE (critical) with --path-len, keyUsage keyCertSign and cRLSign
  (critical), optional critical DNS name constraints, a subject key identifier
  from the CSR key and an authority key identifier from the root.

  The CSR must be PEM ("CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST") or
  bare DER, hold exactly one request with a valid signature, use RSA of 2048
  bits or more or ECDSA P-256/P-384, and carry no unknown critical extension.

  Idempotency: if --cert-out already holds a certificate for the same CSR key
  and subject, with the same profile, signed by this root, and outside its
  renewal window (30 days before expiry, or the last third of its lifetime if
  shorter), nothing is re-signed. A new CSR or changed profile re-signs and
  overwrites --cert-out.

FLAGS
  --cert-out FILE
      write the signed CA certificate (PEM) to this file
  --chain-out FILE
      write the issuer chain (the root) to this file
  --csr FILE
      subordinate-CA CSR file (PEM or DER)
  --dry-run
      report what would change without writing any file
  --fullchain-out FILE
      write the signed certificate then the root to this file
  --not-after DURATION
      certificate validity: a duration (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry (default 10y)
  --password-fd FD
      read the root key password from this inherited file descriptor
  --password-file FILE
      read the root key password from this file
  --password-stdin
      read the root key password from stdin
  --path-len N
      path length constraint of the signed CA (1 allows FreeIPA lightweight sub-CAs)
  --permitted-dns DOMAIN
      permitted DNS domain name constraint (repeatable or comma-separated)
  --quiet
      print nothing on stdout; rely on the exit code
  --root-cert FILE
      root certificate file, instead of --root-dir
  --root-dir DIR
      root directory from root create (holds root.crt and root.key)
  --root-key FILE
      root private key file, instead of --root-dir; - reads stdin

EXAMPLES
  # FreeIPA external CA: sign the CSR, write the cert and the issuer chain
  smallca intermediate sign --root-dir ./ca --csr ipa.csr \
    --cert-out ipa.crt --chain-out ipa-chain.pem --password-file ./root.pass
  # then: ipa-server-install --external-cert-file=ipa.crt --external-cert-file=ipa-chain.pem

  # Allow FreeIPA lightweight sub-CAs (needs a root path length of 2 or more)
  smallca intermediate sign --root-dir ./ca --csr ipa.csr --cert-out ipa.crt \
    --path-len 1 --password-stdin < ./root.pass

OUTPUT
  {"schema_version":1,"changed":true,"cert":"ipa.crt","chain":"ipa-chain.pem",
   "subject":"CN=Certificate Authority,O=EXAMPLE.TEST","serial":"...",
   "fingerprint_sha256":"sha256:...","root_fingerprint_sha256":"sha256:...","not_after":"..."}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca intermediate create

```text
NAME
  smallca intermediate create - generate an intermediate CA key and a root-signed certificate for it

USAGE
  smallca intermediate create (--root-dir DIR | --root-cert FILE --root-key FILE) --subject DN --cert-out FILE --key-out FILE [flags]

DESCRIPTION
  Generates an intermediate CA key and signs a certificate for it with the root in
  --root-dir, for issuers that need the CA key itself, such as a cert-manager CA
  Issuer. The key is written UNENCRYPTED (PKCS#8, mode 0600) because those
  consumers need it in clear: protect it like the secret it is.

  With --k8s-secret-out and --k8s-secret-name it also writes a kubernetes.io/tls
  Secret manifest holding tls.crt (the intermediate), tls.key and ca.crt (the
  root), mode 0600. Never commit or print that file.

  Idempotency: an existing key and certificate are kept when the key matches the
  certificate, the subject and profile equal the request, and the certificate is
  signed by this root and outside its renewal window. An existing pair that
  fails any check is an error: smallca never silently replaces a CA key that
  something may already trust. Move it aside to re-issue.

FLAGS
  --cert-out FILE
      write the intermediate certificate (PEM) to this file
  --chain-out FILE
      write the issuer chain (the root) to this file
  --crv CURVE
      EC curve: P-256 or P-384 (default P-384)
  --dry-run
      report what would change without writing any file
  --fullchain-out FILE
      write the intermediate then the root to this file
  --k8s-secret-name NAME
      metadata.name of the Secret
  --k8s-secret-namespace NAMESPACE
      metadata.namespace of the Secret (optional)
  --k8s-secret-out FILE
      also write a kubernetes.io/tls Secret manifest to this file
  --key-out FILE
      write the unencrypted intermediate key (PEM, mode 0600) to this file
  --kty TYPE
      key type: EC or RSA (default EC)
  --not-after DURATION
      certificate validity: a duration (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry (default 10y)
  --password-fd FD
      read the root key password from this inherited file descriptor
  --password-file FILE
      read the root key password from this file
  --password-stdin
      read the root key password from stdin
  --path-len N
      path length constraint of the intermediate
  --permitted-dns DOMAIN
      permitted DNS domain name constraint (repeatable or comma-separated)
  --quiet
      print nothing on stdout; rely on the exit code
  --root-cert FILE
      root certificate file, instead of --root-dir
  --root-dir DIR
      root directory from root create (holds root.crt and root.key)
  --root-key FILE
      root private key file, instead of --root-dir; - reads stdin
  --size BITS
      RSA key size in bits: 2048, 3072 or 4096 (default 3072)
  --subject DN
      intermediate subject DN

EXAMPLES
  # Intermediate for a cert-manager CA Issuer, limited to example.test names
  smallca intermediate create --root-dir ./ca --subject "CN=Example Issuing CA" \
    --cert-out k8s/ca.crt --key-out k8s/ca.key --fullchain-out k8s/ca-fullchain.pem \
    --permitted-dns example.test \
    --k8s-secret-out k8s/ca-secret.yaml --k8s-secret-name ca-key-pair \
    --k8s-secret-namespace cert-manager --password-file ./root.pass

OUTPUT
  {"schema_version":1,"changed":true,"key":"k8s/ca.key","cert":"k8s/ca.crt",
   "fullchain":"k8s/ca-fullchain.pem","k8s_secret":"k8s/ca-secret.yaml",
   "subject":"CN=Example Issuing CA","serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca leaf create

```text
NAME
  smallca leaf create - issue a server or client certificate from an intermediate

USAGE
  smallca leaf create --issuer-cert FILE --issuer-key FILE --subject NAME --cert-out FILE --key-out FILE [flags]

DESCRIPTION
  Issues an end-entity certificate from an intermediate whose unencrypted key
  smallca can read (see intermediate create). Leaves are never issued straight
  from a self-signed root.

  --purpose sets the extended key usage: server (serverAuth, the default),
  client (clientAuth, for mTLS clients) or both. keyUsage is digitalSignature,
  plus keyEncipherment for RSA keys.

  Names: a subject common name that is a dotted host name (web.example.test) is
  always included as the first DNS SAN, so --subject web.example.test alone is
  enough. Other common names, such as "backup-agent", are not. Each
  --san that parses as an IP address becomes an IP SAN, anything else a DNS SAN.

  Idempotency: the key at --key-out is reused when it exists. The certificate is
  kept when it matches that key, the same subject, SANs and usages, is signed by
  --issuer-cert and is outside its renewal window (30 days before expiry, or the last
  third of its lifetime if shorter); otherwise it is re-issued.

FLAGS
  --cert-out FILE
      write the certificate (PEM) to this file
  --chain-out FILE
      write the issuer chain (the intermediate) to this file
  --crv CURVE
      EC curve: P-256 or P-384 (default P-256)
  --dry-run
      report what would change without writing any file
  --fullchain-out FILE
      write the certificate then the intermediate to this file (what a server presents)
  --issuer-cert FILE
      issuing intermediate certificate file
  --issuer-key FILE
      issuing intermediate private key file (unencrypted)
  --key-out FILE
      write the private key (PEM, mode 0600) to this file; reused if present
  --kty TYPE
      key type: EC or RSA (default EC)
  --not-after DURATION
      certificate validity: a duration (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry (default 90d)
  --purpose SERVER
      what the certificate is for: server, client or both (mTLS peers that accept and make connections) (default server)
  --quiet
      print nothing on stdout; rely on the exit code
  --san NAME
      subject alternative name, DNS name or IP address (repeatable or comma-separated)
  --size BITS
      RSA key size in bits: 2048, 3072 or 4096 (default 3072)
  --subject DN
      subject DN, or a bare common name such as web.example.test

EXAMPLES
  # Server certificate with two DNS names and an IP
  smallca leaf create --issuer-cert k8s/ca.crt --issuer-key k8s/ca.key --subject web.example.test \
    --san web.example.test --san www.example.test --san 192.0.2.10 \
    --cert-out web.crt --key-out web.key --fullchain-out web-fullchain.pem

  # mTLS client certificate valid for 30 days
  smallca leaf create --issuer-cert k8s/ca.crt --issuer-key k8s/ca.key --subject "CN=backup-agent,O=Example" \
    --purpose client --not-after 30d --cert-out agent.crt --key-out agent.key

OUTPUT
  {"schema_version":1,"changed":true,"key":"web.key","cert":"web.crt","fullchain":"web-fullchain.pem",
   "subject":"CN=web.example.test","dns_names":["web.example.test","www.example.test"],
   "ip_addresses":["192.0.2.10"],"serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca leaf sign

```text
NAME
  smallca leaf sign - sign a server or client CSR generated elsewhere

USAGE
  smallca leaf sign --issuer-cert FILE --issuer-key FILE --csr FILE --cert-out FILE [flags]

DESCRIPTION
  Signs an end-entity certificate signing request made by another system, such as
  an appliance, a Java keystore or a service that keeps its own key, with an
  intermediate whose unencrypted key smallca can read.

  Only the subject and public key are taken from the CSR. Key usages are set
  here: --purpose server (serverAuth, the default), client (clientAuth) or both,
  and digitalSignature (plus keyEncipherment for RSA). SANs are copied from the CSR
  unless you give --san, which replaces them; with neither, the subject common
  name becomes the only DNS SAN. Check a CSR first with certificate inspect.

  The CSR must hold one request with a valid signature, RSA of 2048 bits or more
  or ECDSA P-256/P-384, and no unknown critical extension.

  Idempotency: an existing --cert-out for the same key, subject, SANs and usages,
  signed by --issuer-cert and outside its renewal window, is kept.

FLAGS
  --cert-out FILE
      write the certificate (PEM) to this file
  --chain-out FILE
      write the issuer chain (the intermediate) to this file
  --csr FILE
      certificate signing request file (PEM or DER)
  --dry-run
      report what would change without writing any file
  --fullchain-out FILE
      write the certificate then the intermediate to this file
  --issuer-cert FILE
      issuing intermediate certificate file
  --issuer-key FILE
      issuing intermediate private key file (unencrypted)
  --not-after DURATION
      certificate validity: a duration (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry (default 90d)
  --purpose SERVER
      what the certificate is for: server, client or both (mTLS peers that accept and make connections) (default server)
  --quiet
      print nothing on stdout; rely on the exit code
  --san NAME
      replace the CSR's SANs: DNS name or IP address (repeatable or comma-separated)

EXAMPLES
  # Sign a CSR from a switch, keeping the names it asked for
  smallca leaf sign --issuer-cert issuing.crt --issuer-key issuing.key --csr switch1.csr \
    --cert-out switch1.crt --fullchain-out switch1-fullchain.pem

  # Decide the names yourself
  smallca leaf sign --issuer-cert issuing.crt --issuer-key issuing.key --csr app.csr \
    --san app.example.test --san 192.0.2.20 --not-after 30d --cert-out app.crt

OUTPUT
  {"schema_version":1,"changed":true,"cert":"switch1.crt","fullchain":"switch1-fullchain.pem",
   "subject":"CN=switch1.example.test","dns_names":["switch1.example.test"],"ip_addresses":null,
   "serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca csr create

```text
NAME
  smallca csr create - create a key and a certificate signing request for another CA

USAGE
  smallca csr create --subject DN --key-out FILE --csr-out FILE [flags]

DESCRIPTION
  Creates a private key (unencrypted PKCS#8, mode 0600) and a PKCS#10 certificate
  signing request for it, to send to a CA that smallca does not run: a public CA,
  a corporate CA, or another smallca with leaf sign.

  The CSR carries the subject and the --san names only. A subject common name
  that is a dotted host name is always included as the first DNS SAN. Each
  --san that parses as an IP address becomes an IP SAN, anything else a DNS SAN.

  Idempotency: an existing key is reused, and an existing CSR for that key with
  the same subject and SANs is kept.

FLAGS
  --crv CURVE
      EC curve: P-256 or P-384 (default P-256)
  --csr-out FILE
      write the CSR (PEM) to this file
  --dry-run
      report what would change without writing any file
  --key-out FILE
      write the private key (PEM, mode 0600) to this file; reused if present
  --kty TYPE
      key type: EC or RSA (default EC)
  --quiet
      print nothing on stdout; rely on the exit code
  --san NAME
      subject alternative name, DNS name or IP address (repeatable or comma-separated)
  --size BITS
      RSA key size in bits: 2048, 3072 or 4096 (default 3072)
  --subject DN
      subject DN, or a bare common name

EXAMPLES
  # Key and CSR for a public CA
  smallca csr create --subject "CN=www.example.test,O=Example" \
    --san www.example.test --san example.test --key-out www.key --csr-out www.csr

  # RSA for an older appliance
  smallca csr create --subject idrac1.example.test --kty RSA --size 2048 \
    --key-out idrac1.key --csr-out idrac1.csr

OUTPUT
  {"schema_version":1,"changed":true,"key":"www.key","csr":"www.csr",
   "subject":"CN=www.example.test,O=Example","dns_names":["www.example.test","example.test"],"ip_addresses":null}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca certificate inspect

```text
NAME
  smallca certificate inspect - show what is inside a certificate, chain or CSR

USAGE
  smallca certificate inspect (--file FILE | --url HOST[:PORT]) [--json]

DESCRIPTION
  Prints the contents of every certificate in --file, in file order, or of a
  certificate signing request: subject, issuer, serial, validity and days left,
  key type, signature algorithm, CA flag and path length, key usages, SANs, name
  constraints, key identifiers and the SHA-256 fingerprint.

  --file accepts a PEM bundle, DER, PKCS#7 (.p7b) or a CSR (PEM or DER). Use
  "--file -" to read standard input.

  --url connects to a TLS server (host, host:port or https://host:port; port 443
  by default) and shows the chain it presents, without trusting it. smallca opens
  a network connection only when given --url.

  The default output is readable text. --json prints one JSON object instead,
  with "certificates" (a list) or "csr". An expired certificate is still
  inspected and exits 0; use certificate verify to check trust.

FLAGS
  --dry-run
      report what would change without writing any file
  --file FILE
      certificate, chain or CSR file, or - for stdin
  --json
      print one JSON object instead of text
  --quiet
      print nothing on stdout; rely on the exit code
  --servername STRING
      TLS server name (SNI) to send with --url (default: the host)
  --url HOST
      fetch the chain a TLS server presents: host, host:port or https://host:port

EXAMPLES
  # What is in this chain?
  smallca certificate inspect --file web-fullchain.pem

  # What does this server present?
  smallca certificate inspect --url www.example.test

  # A service on another port, with a different SNI name
  smallca certificate inspect --url 192.0.2.10:8443 --servername api.example.test

  # Check a CSR before signing it
  smallca certificate inspect --file ipa.csr

  # Days left on a server's certificate, for a script
  smallca certificate inspect --file web.crt --json | jq '.certificates[0].days_left'

OUTPUT
  Certificate 1 of 1
      Subject:         CN=web.example.test
      Issuer:          CN=Example Issuing CA
      Valid:           2026-11-18T00:00:00Z to 2027-02-16T00:00:00Z (89 days left)
      Key:             EC P-256
      CA:              no
      DNS names:       web.example.test, www.example.test
      SHA-256:         sha256:...

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca certificate verify

```text
NAME
  smallca certificate verify - verify a certificate chains to a trusted root and is not about to expire

USAGE
  smallca certificate verify (--cert FILE | --url HOST[:PORT]) (--roots FILE | --min-remaining DURATION) [flags]

DESCRIPTION
  Verifies the first certificate in --cert, or the one a TLS server presents
  with --url, against the roots in --roots. Further certificates in --cert, the
  server's chain and --chain are used as intermediates. Extra copies of the leaf
  or the root are harmless. Any extended key usage is accepted.

  --min-remaining also fails the check when the certificate expires sooner than
  the given duration, for expiry alerts and deploy gates. With --min-remaining,
  --roots is optional: without it only expiry (and --host) are checked.

  Exit code 0 means every requested check passed; exit code 3 means one did not,
  with the reason in the "error" field. Exit code 1 means an input could not be
  read or the server could not be reached.

FLAGS
  --cert FILE
      certificate file to verify (first certificate; the rest are intermediates)
  --chain FILE
      intermediate certificates file (optional)
  --dry-run
      report what would change without writing any file
  --host NAME
      DNS name the certificate must be valid for (optional)
  --min-remaining DURATION
      fail when the certificate expires within this duration (e.g. 30d)
  --quiet
      print nothing on stdout; rely on the exit code
  --roots FILE
      trusted root certificate(s) file
  --servername STRING
      TLS server name (SNI) to send with --url (default: the host)
  --url HOST
      verify the chain a TLS server presents: host, host:port or https://host:port

EXAMPLES
  # Check a FreeIPA CA certificate against the root
  smallca certificate verify --roots ca/root.crt --cert ipa.crt

  # Check a server chain is valid for a host name
  smallca certificate verify --roots ca/root.crt --cert web-fullchain.pem --host www.example.test

  # Alert when a live server's certificate has less than 14 days left
  smallca certificate verify --url www.example.test --roots ca/root.crt --min-remaining 14d --quiet

OUTPUT
  {"schema_version":1,"valid":true,"subject":"CN=web.example.test",
   "fingerprint_sha256":"sha256:...","not_after":"...","days_left":89,
   "chain":["CN=web.example.test","CN=Example Issuing CA","CN=Example Root CA"]}

EXIT CODES
  0 ok, 1 error, 2 usage error, 3 chain does not verify
```

## smallca certificate match

```text
NAME
  smallca certificate match - check that a certificate, key and CSR belong together

USAGE
  smallca certificate match [--cert FILE] [--key FILE] [--csr FILE] [flags]

DESCRIPTION
  Compares the public keys in a certificate, a private key and a CSR (any two or
  all three) and reports whether they are the same key. Use it before installing
  a certificate, or when a server refuses to start with "key does not match".

  An encrypted key needs one of the password flags. The private key itself is
  never printed: the output holds SHA-256 fingerprints of the public keys only.

  Exit code 0 means they match; exit code 3 means they do not.

FLAGS
  --cert FILE
      certificate file (the first certificate is used)
  --csr FILE
      certificate signing request file
  --dry-run
      report what would change without writing any file
  --key FILE
      private key file
  --password-fd FD
      read the private key password from this inherited file descriptor
  --password-file FILE
      read the private key password from this file
  --password-stdin
      read the private key password from stdin
  --quiet
      print nothing on stdout; rely on the exit code

EXAMPLES
  # Does this certificate go with this key?
  smallca certificate match --cert web.crt --key web.key

  # Did the CA sign the CSR I sent?
  smallca certificate match --cert issued.crt --csr web.csr --key web.key

OUTPUT
  {"schema_version":1,"match":true,"public_keys":{"cert":"sha256:...","key":"sha256:..."}}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca certificate bundle

```text
NAME
  smallca certificate bundle - put certificates from several files into one ordered chain

USAGE
  smallca certificate bundle --cert FILE [--cert FILE ...] --fullchain-out FILE [--include-root]

DESCRIPTION
  Reads certificates from one or more files in any order, drops duplicates, and
  writes them as one chain: the end certificate first, then each issuer. The
  self-signed root is left out unless you give --include-root, because servers
  should not send it.

  It fails when the files hold more than one chain or certificates that do not
  belong to the chain, rather than guessing. A chain whose root was not supplied
  is written as far as it goes, with "ends_at_root": false.

FLAGS
  --cert FILE
      certificate file, PEM bundle, DER or PKCS#7 (repeatable)
  --dry-run
      report what would change without writing any file
  --fullchain-out FILE
      write the ordered chain to this file
  --include-root
      keep the self-signed root at the end of the chain
  --quiet
      print nothing on stdout; rely on the exit code

EXAMPLES
  # A CA sent the certificate and intermediates as separate files
  smallca certificate bundle --cert server.crt --cert intermediate2.crt --cert intermediate1.crt \
    --fullchain-out server-fullchain.pem

OUTPUT
  {"schema_version":1,"changed":true,"fullchain":"server-fullchain.pem",
   "chain":["CN=server.example.test","CN=Example Issuing CA"],"ends_at_root":true}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca certificate convert

```text
NAME
  smallca certificate convert - convert, split or repackage certificates and keys between PEM, DER, PKCS#7 and PKCS#12

USAGE
  smallca certificate convert --in FILE [--in FILE ...] [--format pem|der|p7b] OUTPUTS [(--password-file FILE | --password-stdin | --password-fd N)]

DESCRIPTION
  Reads certificates and at most one private key from every --in file, in any
  of these forms, and writes the outputs you name:

      PEM       certificates, PKCS#7 and private keys (PKCS#8, PKCS#1, SEC1)
      DER       one certificate (.der, .cer)
      PKCS#7    .p7b or .p7c, binary or PEM
      PKCS#12   .p12 or .pfx, with its key, or a Java trust store

  Outputs:

      --out FILE            every certificate, in input order
      --cert-out FILE       the end certificate
      --chain-out FILE      its issuers
      --fullchain-out FILE  the end certificate, then its issuers
      --key-out FILE        the private key, unencrypted PKCS#8 (mode 0600)
      --split-dir DIR       one file per certificate, named N-<common name>.<format>
      --p12-out FILE        PKCS#12 with the key, end certificate and issuers (mode 0600)
      --truststore-out FILE PKCS#12 trust store of every certificate, for Java

  The end certificate is the one the private key matches, or without a key the
  one certificate that signed none of the others. A root in the input stays in
  --chain-out and --fullchain-out; use certificate bundle to drop it.

  --format sets pem, der or p7b for every certificate output. Without it, each
  file's extension decides: .der and .cer are DER, .p7b and .p7c are PKCS#7,
  anything else is PEM. DER holds one certificate only.

  One password covers what needs one: a PKCS#12 or encrypted key input, and
  --p12-out or --truststore-out. Use two runs to change a PKCS#12 password.

  Idempotency: an output whose content would not change is not rewritten, and an
  existing PKCS#12 output that opens with the password and holds the same
  contents is kept.

FLAGS
  --cert-out FILE
      write the end certificate to this file
  --chain-out FILE
      write the issuers of the end certificate to this file
  --dry-run
      report what would change without writing any file
  --format FORMAT
      certificate output format: pem, der or p7b (default: from each file extension)
  --fullchain-out FILE
      write the end certificate and its issuers to this file
  --in FILE
      input file: PEM, DER, PKCS#7 or PKCS#12 (repeatable)
  --key-out FILE
      write the private key, unencrypted, to this file
  --legacy
      use 3DES encryption for systems that cannot read AES-256 PKCS#12
  --out FILE
      write every certificate to this file
  --p12-out FILE
      write a PKCS#12 file with the key and chain to this file
  --password-fd FD
      read the PKCS#12 or key password from this inherited file descriptor
  --password-file FILE
      read the PKCS#12 or key password from this file
  --password-stdin
      read the PKCS#12 or key password from stdin
  --quiet
      print nothing on stdout; rely on the exit code
  --split-dir DIRECTORY
      write each certificate to its own file in this directory
  --truststore-out FILE
      write a PKCS#12 trust store of every certificate to this file

EXAMPLES
  # Split a .pfx into PEM files for nginx
  smallca certificate convert --in web.pfx --password-file pfx.pass \
    --cert-out web.crt --key-out web.key --chain-out chain.pem

  # One DER file per certificate in a PKCS#7 chain
  smallca certificate convert --in chain.p7b --split-dir certs --format der

  # PEM files to a .pfx for Windows
  smallca certificate convert --in web.crt --in web.key --in chain.pem \
    --p12-out web.pfx --password-file pfx.pass

  # A Java trust store of a root bundle
  smallca certificate convert --in roots.pem --truststore-out roots.p12 --password-file ts.pass

OUTPUT
  {"schema_version":1,"changed":true,"certificates":["CN=web.example.test","CN=Example Issuing CA"],"has_key":true}

EXIT CODES
  0 ok, 1 error, 2 usage error
```

## smallca mtls verify

```text
NAME
  smallca mtls verify - check that a server and a client certificate trust each other for mutual TLS

USAGE
  smallca mtls verify --server-cert FILE --client-cert FILE --server-trust FILE --client-trust FILE [flags]
  smallca mtls verify --url HOST[:PORT] --client-cert FILE --client-key FILE --client-trust FILE

DESCRIPTION
  Answers "will these two sides accept each other?" before you find out in a
  handshake log.

  Offline (the default) it checks both directions the way TLS libraries do:
    - client trusts server certificate: the server certificate chains to the CA
      bundle the client trusts (--client-trust), has the serverAuth usage, is in
      date, and, with --host, is valid for the name the client connects to;
    - server trusts client certificate: the client certificate chains to the CA
      bundle the server trusts (--server-trust), has the clientAuth usage and is
      in date;
    - with --server-key or --client-key, each key matches its certificate.
  Put intermediates after the certificate in --server-cert and --client-cert, as
  the peer would send them.

  With --url it connects to a live server as the client: it presents
  --client-cert, checks the server certificate against --client-trust, and
  reports whether the server accepted the client certificate.

  Every check is listed with ok true or false and the reason. Exit code 0 means
  all passed; exit code 3 means at least one failed.

FLAGS
  --client-cert FILE
      client certificate file, intermediates after it
  --client-key FILE
      client private key file (needed with --url)
  --client-trust FILE
      CA certificates file the client trusts the server with
  --dry-run
      report what would change without writing any file
  --host NAME
      DNS name the client connects to (offline check)
  --quiet
      print nothing on stdout; rely on the exit code
  --server-cert FILE
      server certificate file, intermediates after it
  --server-key FILE
      server private key file (optional, checks it matches)
  --server-trust FILE
      CA certificates file the server trusts client certificates with
  --servername STRING
      TLS server name (SNI) to send with --url (default: the host)
  --url HOST
      test a live server: host, host:port or https://host:port

EXAMPLES
  # Before deploying: will the agent and the API accept each other?
  smallca mtls verify --server-cert api-fullchain.pem --server-key api.key \
    --server-trust clients-ca.pem --client-cert agent-fullchain.pem --client-key agent.key \
    --client-trust root.crt --host api.example.test

  # Against the running server
  smallca mtls verify --url api.example.test:8443 --client-cert agent-fullchain.pem \
    --client-key agent.key --client-trust root.crt

OUTPUT
  {"schema_version":1,"valid":false,"checks":[
   {"check":"client trusts server certificate","ok":true,"detail":"CN=api.example.test -> CN=Example Issuing CA -> CN=Example Root CA"},
   {"check":"server trusts client certificate","ok":false,"detail":"x509: certificate specifies an incompatible key usage"}]}

EXIT CODES
  0 ok, 1 error, 2 usage error
```
