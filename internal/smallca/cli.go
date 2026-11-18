package smallca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/newen-systems/smallca/internal/passphrase"
)

// Version and Commit are set at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
)

// SchemaVersion is the version of every JSON object smallca prints.
const SchemaVersion = 1

// Exit codes.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitInvalid = 3 // certificate verify: the chain does not verify
)

// cont is the "keep going" sentinel returned by the helpers below in place of
// an exit code.
const cont = -1

// env carries the streams of one invocation.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	quiet          bool
}

// command is one noun-verb subcommand. setup registers its flags on fs and
// returns the function that runs it after parsing.
type command struct {
	name     string // "root create"
	summary  string
	synopsis string
	desc     string
	examples string
	output   string
	setup    func(fs *flag.FlagSet) func(e *env) int
}

// commands is the CLI, in help order.
var commands = []*command{rootCreate, intermediateSign, intermediateCreate, leafCreate, leafSign, csrCreate,
	certificateInspect, certificateVerify, certificateMatch, certificateBundle, certificateConvert, mtlsVerify}

func lookup(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

// Run is the CLI entry point; main wraps it with the real streams.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) == 0 {
		return usageErr(e, "no command given; run 'smallca help'")
	}
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) > 1 {
			if c := lookup(strings.Join(args[1:], " ")); c != nil {
				writeHelp(stdout, c)
				return ExitOK
			}
			return usageErr(e, fmt.Sprintf("unknown command %q; run 'smallca help'", strings.Join(args[1:], " ")))
		}
		writeMainHelp(stdout)
		return ExitOK
	case "version", "--version":
		return writeJSON(e, map[string]string{"version": Version, "commit": Commit})
	}
	var c *command
	rest := args[1:]
	if len(args) > 1 {
		c = lookup(args[0] + " " + args[1])
		rest = args[2:]
	}
	if c == nil {
		name := args[0]
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			name += " " + args[1]
		}
		return usageErr(e, fmt.Sprintf("unknown command %q; run 'smallca help'", name))
	}
	return c.run(e, rest)
}

func (c *command) run(e *env, args []string) int {
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&e.quiet, "quiet", false, "print nothing on stdout; rely on the exit code")
	fs.BoolVar(&dryRun, "dry-run", false, "report what would change without writing any file")
	defer func() { dryRun = false }()
	run := c.setup(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeHelp(e.stdout, c)
			return ExitOK
		}
		return usageErr(e, fmt.Sprintf("%v; run 'smallca %s --help'", err, c.name))
	}
	if fs.NArg() > 0 {
		return usageErr(e, fmt.Sprintf("unexpected arguments: %s", strings.Join(fs.Args(), " ")))
	}
	return run(e)
}

// ---- output ----

// writeJSON prints v as one JSON object with schema_version added.
func writeJSON(e *env, v any) int {
	if e.quiet {
		return ExitOK
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fail(e, "internal", err)
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fail(e, "internal", err)
	}
	m["schema_version"] = json.RawMessage(fmt.Sprint(SchemaVersion))
	if dryRun {
		m["dry_run"] = json.RawMessage("true")
	}
	if err := json.NewEncoder(e.stdout).Encode(m); err != nil {
		return ExitError
	}
	return ExitOK
}

// diag prints one error as a JSON line on stderr.
func diag(e *env, code, msg string) {
	_ = json.NewEncoder(e.stderr).Encode(map[string]any{
		"schema_version": SchemaVersion, "code": code, "message": msg,
	})
}

func fail(e *env, code string, err error) int {
	diag(e, code, err.Error())
	return ExitError
}

func usageErr(e *env, msg string) int {
	diag(e, "usage", msg)
	return ExitUsage
}

// ---- flag helpers ----

// stringList is a repeatable flag that also splits on commas.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// required reports every missing required flag at once.
func required(e *env, pairs ...string) int {
	var missing []string
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			missing = append(missing, "--"+pairs[i])
		}
	}
	if len(missing) > 0 {
		return usageErr(e, "missing required flags: "+strings.Join(missing, ", "))
	}
	return cont
}

// keyFlags registers --kty, --crv and --size.
func keyFlags(fs *flag.FlagSet, defCrv string) func(e *env) (KeySpec, int) {
	var s KeySpec
	fs.StringVar(&s.Kty, "kty", "EC", "key `type`: EC or RSA")
	fs.StringVar(&s.Crv, "crv", "", "EC `curve`: P-256 or P-384 (default "+defCrv+")")
	fs.IntVar(&s.Size, "size", 0, "RSA key size in `bits`: 2048, 3072 or 4096 (default 3072)")
	return func(e *env) (KeySpec, int) {
		r, err := s.Resolve(defCrv)
		if err != nil {
			return r, usageErr(e, err.Error())
		}
		return r, cont
	}
}

// notAfterFlag registers --not-after.
func notAfterFlag(fs *flag.FlagSet, def, what string) *string {
	return fs.String("not-after", def, what+" validity: a `duration` (90d, 10y, 36h) or an RFC 3339 time; capped at the issuer's expiry")
}

func parseNotAfter(e *env, s string) (time.Duration, int) {
	d, err := ParseNotAfter(s)
	if err != nil {
		return 0, usageErr(e, "--not-after: "+err.Error())
	}
	return d, cont
}

// passwordFlags registers the three password sources for the root key. With
// required false, no source at all returns a nil password.
func passwordFlags(fs *flag.FlagSet, required bool, what string) func(e *env) ([]byte, int) {
	file := fs.String("password-file", "", "read the "+what+" password from this `file`")
	stdin := fs.Bool("password-stdin", false, "read the "+what+" password from stdin")
	fd := fs.Uint("password-fd", 0, "read the "+what+" password from this inherited file descriptor")
	return func(e *env) ([]byte, int) {
		n := 0
		for _, set := range []bool{*file != "", *stdin, *fd != 0} {
			if set {
				n++
			}
		}
		if n == 0 && !required {
			return nil, cont
		}
		if n != 1 {
			return nil, usageErr(e, "exactly one of --password-file, --password-stdin or --password-fd is required")
		}
		var p []byte
		var err error
		switch {
		case *file != "":
			p, err = passphrase.FromFile(*file)
		case *stdin:
			p, err = passphrase.Read(e.stdin)
		default:
			p, err = passphrase.FromFD(uintptr(*fd))
		}
		if err != nil {
			return nil, fail(e, "password_unavailable", err)
		}
		return p, cont
	}
}

// rootFlags registers where the signing root comes from: --root-dir, or
// --root-cert and --root-key from any path (a pipe, /dev/fd/N, process
// substitution, or - for stdin), plus the password flags.
func rootFlags(fs *flag.FlagSet) func(e *env) (*Root, int) {
	dir := fs.String("root-dir", "", "root `dir`ectory from root create (holds root.crt and root.key)")
	certPath := fs.String("root-cert", "", "root certificate `file`, instead of --root-dir")
	keyPath := fs.String("root-key", "", "root private key `file`, instead of --root-dir; - reads stdin")
	getPass := passwordFlags(fs, false, "root key")
	return func(e *env) (*Root, int) {
		switch {
		case *dir != "" && (*certPath != "" || *keyPath != ""):
			return nil, usageErr(e, "give --root-dir or --root-cert and --root-key, not both")
		case *dir != "":
			*certPath, *keyPath = RootPaths(*dir)
		case *certPath == "" || *keyPath == "":
			return nil, usageErr(e, "missing required flags: --root-dir, or --root-cert and --root-key")
		}
		if *keyPath == "-" && fs.Lookup("password-stdin").Value.String() == "true" {
			return nil, usageErr(e, "--root-key - and --password-stdin cannot both read stdin")
		}
		certPEM, err := readInput(*certPath, e.stdin)
		if err != nil {
			return nil, fail(e, "root_unavailable", err)
		}
		keyPEM, err := readInput(*keyPath, e.stdin)
		if err != nil {
			return nil, fail(e, "root_unavailable", err)
		}
		defer passphrase.Clear(keyPEM)
		pass, rc := getPass(e)
		if rc != cont {
			return nil, rc
		}
		defer passphrase.Clear(pass)
		switch enc := KeyEncrypted(keyPEM); {
		case enc && pass == nil:
			return nil, usageErr(e, "the root key is encrypted: give --password-file, --password-stdin or --password-fd")
		case !enc && pass != nil:
			return nil, usageErr(e, "a password was given but the root key is not encrypted")
		}
		root, err := ParseRoot(certPEM, keyPEM, pass)
		if err != nil {
			return nil, fail(e, "root_unavailable", err)
		}
		return root, cont
	}
}

// ---- commands ----

// Output flag names shared by several commands.
const (
	flagCertOut      = "cert-out"
	flagChainOut     = "chain-out"
	flagFullchainOut = "fullchain-out"
	flagKeyOut       = "key-out"
	flagP12Out       = "p12-out"
	flagIssuerCert   = "issuer-cert"
	flagIssuerKey    = "issuer-key"
)

const passwordSynopsis = "(--password-file FILE | --password-stdin | --password-fd N)"

var rootCreate = &command{
	name:     "root create",
	summary:  "create the root CA in a directory, or check the existing one",
	synopsis: "smallca root create --root-dir DIR --subject DN [flags] " + passwordSynopsis,
	desc: `Creates DIR/root.crt and DIR/root.key, a self-signed root CA whose private
key is stored as PKCS#8 encrypted with the given password. The root profile is
CA:TRUE (critical) with the given path length, and keyUsage keyCertSign and
cRLSign (critical).

If the root already exists, root create decrypts the key, checks it matches the
certificate and that the subject equals --subject, and reports changed:false.
It never overwrites an existing root.`,
	examples: `  # Create a root, reading the password from a file
  smallca root create --root-dir ./ca --subject "CN=Example Root CA,O=Example" \
    --password-file ./root.pass

  # Same, from Ansible's command module (stdin: "{{ root_password }}")
  smallca root create --root-dir ./ca --subject "CN=Example Root CA" --password-stdin`,
	output: `{"schema_version":1,"changed":true,"root_cert":"ca/root.crt","root_key":"ca/root.key",
 "subject":"CN=Example Root CA,O=Example","serial":"...","fingerprint_sha256":"sha256:...",
 "not_after":"2046-11-17T00:00:00Z"}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		dir := fs.String("root-dir", "", "`dir`ectory for root.crt and root.key (created mode 0700)")
		subject := fs.String("subject", "", "root subject `DN`, e.g. \"CN=Example Root CA,O=Example\"")
		key := keyFlags(fs, "P-384")
		notAfter := notAfterFlag(fs, "20y", "root")
		pathLen := fs.Int("path-len", 2, "root path length constraint (-1 for none)")
		getPass := passwordFlags(fs, true, "root key")
		return func(e *env) int {
			if rc := required(e, "root-dir", *dir, "subject", *subject); rc != cont {
				return rc
			}
			k, rc := key(e)
			if rc != cont {
				return rc
			}
			v, rc := parseNotAfter(e, *notAfter)
			if rc != cont {
				return rc
			}
			pass, rc := getPass(e)
			if rc != cont {
				return rc
			}
			defer passphrase.Clear(pass)
			res, err := CreateRoot(RootOptions{Dir: *dir, Subject: *subject, Key: k, Validity: v, PathLen: *pathLen}, pass)
			if err != nil {
				return fail(e, "root_create_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var intermediateSign = &command{
	name:     "intermediate sign",
	summary:  "sign an externally generated subordinate-CA CSR with the root",
	synopsis: "smallca intermediate sign (--root-dir DIR | --root-cert FILE --root-key FILE) --csr FILE --cert-out FILE [flags]",
	desc: `Signs a subordinate-CA certificate signing request, for example the
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
overwrites --cert-out.`,
	examples: `  # FreeIPA external CA: sign the CSR, write the cert and the issuer chain
  smallca intermediate sign --root-dir ./ca --csr ipa.csr \
    --cert-out ipa.crt --chain-out ipa-chain.pem --password-file ./root.pass
  # then: ipa-server-install --external-cert-file=ipa.crt --external-cert-file=ipa-chain.pem

  # Allow FreeIPA lightweight sub-CAs (needs a root path length of 2 or more)
  smallca intermediate sign --root-dir ./ca --csr ipa.csr --cert-out ipa.crt \
    --path-len 1 --password-stdin < ./root.pass`,
	output: `{"schema_version":1,"changed":true,"cert":"ipa.crt","chain":"ipa-chain.pem",
 "subject":"CN=Certificate Authority,O=EXAMPLE.TEST","serial":"...",
 "fingerprint_sha256":"sha256:...","root_fingerprint_sha256":"sha256:...","not_after":"..."}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		csr := fs.String("csr", "", "subordinate-CA CSR `file` (PEM or DER)")
		certOut := fs.String(flagCertOut, "", "write the signed CA certificate (PEM) to this `file`")
		chainOut := fs.String(flagChainOut, "", "write the issuer chain (the root) to this `file`")
		fullOut := fs.String(flagFullchainOut, "", "write the signed certificate then the root to this `file`")
		notAfter := notAfterFlag(fs, "10y", "certificate")
		pathLen := fs.Int("path-len", 0, "path length constraint of the signed CA (1 allows FreeIPA lightweight sub-CAs)")
		var dns stringList
		fs.Var(&dns, "permitted-dns", "permitted DNS `domain` name constraint (repeatable or comma-separated)")
		getRoot := rootFlags(fs)
		return func(e *env) int {
			if rc := required(e, "csr", *csr, flagCertOut, *certOut); rc != cont {
				return rc
			}
			v, rc := parseNotAfter(e, *notAfter)
			if rc != cont {
				return rc
			}
			root, rc := getRoot(e)
			if rc != cont {
				return rc
			}
			res, err := SignCSR(root, SignOptions{CSRPath: *csr, CertOut: *certOut, ChainOut: *chainOut,
				FullchainOut: *fullOut, Validity: v, PathLen: *pathLen, PermittedDNS: dns})
			if err != nil {
				return fail(e, "sign_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var intermediateCreate = &command{
	name:     "intermediate create",
	summary:  "generate an intermediate CA key and a root-signed certificate for it",
	synopsis: "smallca intermediate create (--root-dir DIR | --root-cert FILE --root-key FILE) --subject DN --cert-out FILE --key-out FILE [flags]",
	desc: `Generates an intermediate CA key and signs a certificate for it with the root in
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
something may already trust. Move it aside to re-issue.`,
	examples: `  # Intermediate for a cert-manager CA Issuer, limited to example.test names
  smallca intermediate create --root-dir ./ca --subject "CN=Example Issuing CA" \
    --cert-out k8s/ca.crt --key-out k8s/ca.key --fullchain-out k8s/ca-fullchain.pem \
    --permitted-dns example.test \
    --k8s-secret-out k8s/ca-secret.yaml --k8s-secret-name ca-key-pair \
    --k8s-secret-namespace cert-manager --password-file ./root.pass`,
	output: `{"schema_version":1,"changed":true,"key":"k8s/ca.key","cert":"k8s/ca.crt",
 "fullchain":"k8s/ca-fullchain.pem","k8s_secret":"k8s/ca-secret.yaml",
 "subject":"CN=Example Issuing CA","serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		subject := fs.String("subject", "", "intermediate subject `DN`")
		certOut := fs.String(flagCertOut, "", "write the intermediate certificate (PEM) to this `file`")
		keyOut := fs.String(flagKeyOut, "", "write the unencrypted intermediate key (PEM, mode 0600) to this `file`")
		chainOut := fs.String(flagChainOut, "", "write the issuer chain (the root) to this `file`")
		fullOut := fs.String(flagFullchainOut, "", "write the intermediate then the root to this `file`")
		key := keyFlags(fs, "P-384")
		notAfter := notAfterFlag(fs, "10y", "certificate")
		pathLen := fs.Int("path-len", 0, "path length constraint of the intermediate")
		var dns stringList
		fs.Var(&dns, "permitted-dns", "permitted DNS `domain` name constraint (repeatable or comma-separated)")
		secretOut := fs.String("k8s-secret-out", "", "also write a kubernetes.io/tls Secret manifest to this `file`")
		secretName := fs.String("k8s-secret-name", "", "metadata.name of the Secret")
		secretNS := fs.String("k8s-secret-namespace", "", "metadata.namespace of the Secret (optional)")
		getRoot := rootFlags(fs)
		return func(e *env) int {
			if rc := required(e, "subject", *subject, flagCertOut, *certOut, flagKeyOut, *keyOut); rc != cont {
				return rc
			}
			if (*secretOut == "") != (*secretName == "") {
				return usageErr(e, "--k8s-secret-out and --k8s-secret-name go together")
			}
			k, rc := key(e)
			if rc != cont {
				return rc
			}
			v, rc := parseNotAfter(e, *notAfter)
			if rc != cont {
				return rc
			}
			root, rc := getRoot(e)
			if rc != cont {
				return rc
			}
			res, err := Intermediate(root, IntermediateOptions{Subject: *subject, CertOut: *certOut, KeyOut: *keyOut,
				ChainOut: *chainOut, FullchainOut: *fullOut, Key: k, Validity: v, PathLen: *pathLen, PermittedDNS: dns,
				SecretOut: *secretOut, SecretName: *secretName, SecretNS: *secretNS})
			if err != nil {
				return fail(e, "intermediate_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var leafCreate = &command{
	name:     "leaf create",
	summary:  "issue a server or client certificate from an intermediate",
	synopsis: "smallca leaf create --issuer-cert FILE --issuer-key FILE --subject NAME --cert-out FILE --key-out FILE [flags]",
	desc: `Issues an end-entity certificate from an intermediate whose unencrypted key
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
third of its lifetime if shorter); otherwise it is re-issued.`,
	examples: `  # Server certificate with two DNS names and an IP
  smallca leaf create --issuer-cert k8s/ca.crt --issuer-key k8s/ca.key --subject web.example.test \
    --san web.example.test --san www.example.test --san 192.0.2.10 \
    --cert-out web.crt --key-out web.key --fullchain-out web-fullchain.pem

  # mTLS client certificate valid for 30 days
  smallca leaf create --issuer-cert k8s/ca.crt --issuer-key k8s/ca.key --subject "CN=backup-agent,O=Example" \
    --purpose client --not-after 30d --cert-out agent.crt --key-out agent.key`,
	output: `{"schema_version":1,"changed":true,"key":"web.key","cert":"web.crt","fullchain":"web-fullchain.pem",
 "subject":"CN=web.example.test","dns_names":["web.example.test","www.example.test"],
 "ip_addresses":["192.0.2.10"],"serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		caCert := fs.String(flagIssuerCert, "", "issuing intermediate certificate `file`")
		caKey := fs.String(flagIssuerKey, "", "issuing intermediate private key `file` (unencrypted)")
		subject := fs.String("subject", "", "subject `DN`, or a bare common name such as web.example.test")
		var sans stringList
		fs.Var(&sans, "san", "subject alternative `name`, DNS name or IP address (repeatable or comma-separated)")
		certOut := fs.String(flagCertOut, "", "write the certificate (PEM) to this `file`")
		keyOut := fs.String(flagKeyOut, "", "write the private key (PEM, mode 0600) to this `file`; reused if present")
		chainOut := fs.String(flagChainOut, "", "write the issuer chain (the intermediate) to this `file`")
		fullOut := fs.String(flagFullchainOut, "", "write the certificate then the intermediate to this `file` (what a server presents)")
		key := keyFlags(fs, "P-256")
		notAfter := notAfterFlag(fs, "90d", "certificate")
		purpose := fs.String("purpose", "server", "what the certificate is for: `server`, client or both (mTLS peers that accept and make connections)")
		return func(e *env) int {
			if rc := required(e, flagIssuerCert, *caCert, flagIssuerKey, *caKey, "subject", *subject, flagCertOut, *certOut, flagKeyOut, *keyOut); rc != cont {
				return rc
			}
			k, rc := key(e)
			if rc != cont {
				return rc
			}
			v, rc := parseNotAfter(e, *notAfter)
			if rc != cont {
				return rc
			}
			dns, ips, rc := leafNames(e, *subject, sans)
			if rc != cont {
				return rc
			}
			res, err := Leaf(LeafOptions{CACert: *caCert, CAKey: *caKey, Subject: *subject, DNS: dns, IPs: ips,
				CertOut: *certOut, KeyOut: *keyOut, ChainOut: *chainOut, FullchainOut: *fullOut, Validity: v, Key: k, Purpose: *purpose})
			if err != nil {
				return fail(e, "leaf_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var certificateInspect = &command{
	name:     "certificate inspect",
	summary:  "show what is inside a certificate, chain or CSR",
	synopsis: "smallca certificate inspect (--file FILE | --url HOST[:PORT]) [--json]",
	desc: `Prints the contents of every certificate in --file, in file order, or of a
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
inspected and exits 0; use certificate verify to check trust.`,
	examples: `  # What is in this chain?
  smallca certificate inspect --file web-fullchain.pem

  # What does this server present?
  smallca certificate inspect --url www.example.test

  # A service on another port, with a different SNI name
  smallca certificate inspect --url 192.0.2.10:8443 --servername api.example.test

  # Check a CSR before signing it
  smallca certificate inspect --file ipa.csr

  # Days left on a server's certificate, for a script
  smallca certificate inspect --file web.crt --json | jq '.certificates[0].days_left'`,
	output: `Certificate 1 of 1
    Subject:         CN=web.example.test
    Issuer:          CN=Example Issuing CA
    Valid:           2026-11-18T00:00:00Z to 2027-02-16T00:00:00Z (89 days left)
    Key:             EC P-256
    CA:              no
    DNS names:       web.example.test, www.example.test
    SHA-256:         sha256:...`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		cert := fs.String("file", "", "certificate, chain or CSR `file`, or - for stdin")
		target := fs.String("url", "", "fetch the chain a TLS server presents: `host`, host:port or https://host:port")
		sni := fs.String("servername", "", "TLS server name (SNI) to send with --url (default: the host)")
		asJSON := fs.Bool("json", false, "print one JSON object instead of text")
		return func(e *env) int {
			if (*cert == "") == (*target == "") {
				return usageErr(e, "give exactly one of --file or --url")
			}
			var res *InspectResult
			if *target != "" {
				certs, _, err := FetchChain(context.Background(), *target, *sni)
				if err != nil {
					return fail(e, "fetch_failed", err)
				}
				res = &InspectResult{}
				for _, c := range certs {
					res.Certificates = append(res.Certificates, viewCert(c))
				}
			} else {
				data, err := readInput(*cert, e.stdin)
				if err != nil {
					return fail(e, "inspect_failed", err)
				}
				if res, err = Inspect(data); err != nil {
					return fail(e, "inspect_failed", err)
				}
			}
			if *asJSON {
				return writeJSON(e, res)
			}
			if !e.quiet {
				writeInspectText(e.stdout, res)
			}
			return ExitOK
		}
	},
}

var certificateVerify = &command{
	name:     "certificate verify",
	summary:  "verify a certificate chains to a trusted root and is not about to expire",
	synopsis: "smallca certificate verify (--cert FILE | --url HOST[:PORT]) (--roots FILE | --min-remaining DURATION) [flags]",
	desc: `Verifies the first certificate in --cert, or the one a TLS server presents
with --url, against the roots in --roots. Further certificates in --cert, the
server's chain and --chain are used as intermediates. Extra copies of the leaf
or the root are harmless. Any extended key usage is accepted.

--min-remaining also fails the check when the certificate expires sooner than
the given duration, for expiry alerts and deploy gates. With --min-remaining,
--roots is optional: without it only expiry (and --host) are checked.

Exit code 0 means every requested check passed; exit code 3 means one did not,
with the reason in the "error" field. Exit code 1 means an input could not be
read or the server could not be reached.`,
	examples: `  # Check a FreeIPA CA certificate against the root
  smallca certificate verify --roots ca/root.crt --cert ipa.crt

  # Check a server chain is valid for a host name
  smallca certificate verify --roots ca/root.crt --cert web-fullchain.pem --host www.example.test

  # Alert when a live server's certificate has less than 14 days left
  smallca certificate verify --url www.example.test --roots ca/root.crt --min-remaining 14d --quiet`,
	output: `{"schema_version":1,"valid":true,"subject":"CN=web.example.test",
 "fingerprint_sha256":"sha256:...","not_after":"...","days_left":89,
 "chain":["CN=web.example.test","CN=Example Issuing CA","CN=Example Root CA"]}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		cert := fs.String("cert", "", "certificate `file` to verify (first certificate; the rest are intermediates)")
		target := fs.String("url", "", "verify the chain a TLS server presents: `host`, host:port or https://host:port")
		sni := fs.String("servername", "", "TLS server name (SNI) to send with --url (default: the host)")
		roots := fs.String("roots", "", "trusted root certificate(s) `file`")
		chain := fs.String("chain", "", "intermediate certificates `file` (optional)")
		host := fs.String("host", "", "DNS `name` the certificate must be valid for (optional)")
		minLeft := fs.String("min-remaining", "", "fail when the certificate expires within this `duration` (e.g. 30d)")
		return func(e *env) int {
			if (*cert == "") == (*target == "") {
				return usageErr(e, "give exactly one of --cert or --url")
			}
			if *roots == "" && *minLeft == "" {
				return usageErr(e, "missing required flags: --roots, or --min-remaining for an expiry-only check")
			}
			var min time.Duration
			if *minLeft != "" {
				d, err := ParseDuration(*minLeft)
				if err != nil {
					return usageErr(e, "--min-remaining: "+err.Error())
				}
				min = d
			}
			var certs, rootCerts, inter []*x509.Certificate
			var err error
			if *target != "" {
				if certs, _, err = FetchChain(context.Background(), *target, *sni); err != nil {
					return fail(e, "fetch_failed", err)
				}
				if *host == "" {
					*host = *sni
				}
			} else if certs, err = readCerts(*cert); err != nil {
				return fail(e, "verify_failed", err)
			}
			if *roots != "" {
				if rootCerts, err = readCerts(*roots); err != nil {
					return fail(e, "verify_failed", err)
				}
			}
			if *chain != "" {
				if inter, err = readCerts(*chain); err != nil {
					return fail(e, "verify_failed", err)
				}
			}
			res := Verify(rootCerts, certs, inter, *host, min)
			if rc := writeJSON(e, res); rc != ExitOK {
				return rc
			}
			if !res.Valid {
				return ExitInvalid
			}
			return ExitOK
		}
	},
}

var leafSign = &command{
	name:     "leaf sign",
	summary:  "sign a server or client CSR generated elsewhere",
	synopsis: "smallca leaf sign --issuer-cert FILE --issuer-key FILE --csr FILE --cert-out FILE [flags]",
	desc: `Signs an end-entity certificate signing request made by another system, such as
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
signed by --issuer-cert and outside its renewal window, is kept.`,
	examples: `  # Sign a CSR from a switch, keeping the names it asked for
  smallca leaf sign --issuer-cert issuing.crt --issuer-key issuing.key --csr switch1.csr \
    --cert-out switch1.crt --fullchain-out switch1-fullchain.pem

  # Decide the names yourself
  smallca leaf sign --issuer-cert issuing.crt --issuer-key issuing.key --csr app.csr \
    --san app.example.test --san 192.0.2.20 --not-after 30d --cert-out app.crt`,
	output: `{"schema_version":1,"changed":true,"cert":"switch1.crt","fullchain":"switch1-fullchain.pem",
 "subject":"CN=switch1.example.test","dns_names":["switch1.example.test"],"ip_addresses":null,
 "serial":"...","fingerprint_sha256":"sha256:...","not_after":"..."}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		caCert := fs.String(flagIssuerCert, "", "issuing intermediate certificate `file`")
		caKey := fs.String(flagIssuerKey, "", "issuing intermediate private key `file` (unencrypted)")
		csr := fs.String("csr", "", "certificate signing request `file` (PEM or DER)")
		var sans stringList
		fs.Var(&sans, "san", "replace the CSR's SANs: DNS `name` or IP address (repeatable or comma-separated)")
		certOut := fs.String(flagCertOut, "", "write the certificate (PEM) to this `file`")
		chainOut := fs.String(flagChainOut, "", "write the issuer chain (the intermediate) to this `file`")
		fullOut := fs.String(flagFullchainOut, "", "write the certificate then the intermediate to this `file`")
		notAfter := notAfterFlag(fs, "90d", "certificate")
		purpose := fs.String("purpose", "server", "what the certificate is for: `server`, client or both (mTLS peers that accept and make connections)")
		return func(e *env) int {
			if rc := required(e, flagIssuerCert, *caCert, flagIssuerKey, *caKey, "csr", *csr, flagCertOut, *certOut); rc != cont {
				return rc
			}
			v, rc := parseNotAfter(e, *notAfter)
			if rc != cont {
				return rc
			}
			dns, ips := splitSANs(sans)
			res, err := LeafSign(LeafSignOptions{CACert: *caCert, CAKey: *caKey, CSRPath: *csr, DNS: dns, IPs: ips,
				CertOut: *certOut, ChainOut: *chainOut, FullchainOut: *fullOut, Validity: v, Purpose: *purpose})
			if err != nil {
				return fail(e, "sign_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var csrCreate = &command{
	name:     "csr create",
	summary:  "create a key and a certificate signing request for another CA",
	synopsis: "smallca csr create --subject DN --key-out FILE --csr-out FILE [flags]",
	desc: `Creates a private key (unencrypted PKCS#8, mode 0600) and a PKCS#10 certificate
signing request for it, to send to a CA that smallca does not run: a public CA,
a corporate CA, or another smallca with leaf sign.

The CSR carries the subject and the --san names only. A subject common name
that is a dotted host name is always included as the first DNS SAN. Each
--san that parses as an IP address becomes an IP SAN, anything else a DNS SAN.

Idempotency: an existing key is reused, and an existing CSR for that key with
the same subject and SANs is kept.`,
	examples: `  # Key and CSR for a public CA
  smallca csr create --subject "CN=www.example.test,O=Example" \
    --san www.example.test --san example.test --key-out www.key --csr-out www.csr

  # RSA for an older appliance
  smallca csr create --subject idrac1.example.test --kty RSA --size 2048 \
    --key-out idrac1.key --csr-out idrac1.csr`,
	output: `{"schema_version":1,"changed":true,"key":"www.key","csr":"www.csr",
 "subject":"CN=www.example.test,O=Example","dns_names":["www.example.test","example.test"],"ip_addresses":null}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		subject := fs.String("subject", "", "subject `DN`, or a bare common name")
		var sans stringList
		fs.Var(&sans, "san", "subject alternative `name`, DNS name or IP address (repeatable or comma-separated)")
		keyOut := fs.String(flagKeyOut, "", "write the private key (PEM, mode 0600) to this `file`; reused if present")
		csrOut := fs.String("csr-out", "", "write the CSR (PEM) to this `file`")
		key := keyFlags(fs, "P-256")
		return func(e *env) int {
			if rc := required(e, "subject", *subject, flagKeyOut, *keyOut, "csr-out", *csrOut); rc != cont {
				return rc
			}
			k, rc := key(e)
			if rc != cont {
				return rc
			}
			dns, ips, rc := leafNames(e, *subject, sans)
			if rc != cont {
				return rc
			}
			res, err := CreateCSR(CSROptions{Subject: *subject, DNS: dns, IPs: ips, KeyOut: *keyOut, CSROut: *csrOut, Key: k})
			if err != nil {
				return fail(e, "csr_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var certificateMatch = &command{
	name:     "certificate match",
	summary:  "check that a certificate, key and CSR belong together",
	synopsis: "smallca certificate match [--cert FILE] [--key FILE] [--csr FILE] [flags]",
	desc: `Compares the public keys in a certificate, a private key and a CSR (any two or
all three) and reports whether they are the same key. Use it before installing
a certificate, or when a server refuses to start with "key does not match".

An encrypted key needs one of the password flags. The private key itself is
never printed: the output holds SHA-256 fingerprints of the public keys only.

Exit code 0 means they match; exit code 3 means they do not.`,
	examples: `  # Does this certificate go with this key?
  smallca certificate match --cert web.crt --key web.key

  # Did the CA sign the CSR I sent?
  smallca certificate match --cert issued.crt --csr web.csr --key web.key`,
	output: `{"schema_version":1,"match":true,"public_keys":{"cert":"sha256:...","key":"sha256:..."}}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		cert := fs.String("cert", "", "certificate `file` (the first certificate is used)")
		key := fs.String("key", "", "private key `file`")
		csr := fs.String("csr", "", "certificate signing request `file`")
		getPass := passwordFlags(fs, false, "private key")
		return func(e *env) int {
			pass, rc := getPass(e)
			if rc != cont {
				return rc
			}
			defer passphrase.Clear(pass)
			res, err := Match(*cert, *key, *csr, pass)
			if err != nil {
				return fail(e, "match_failed", err)
			}
			if rc := writeJSON(e, res); rc != ExitOK {
				return rc
			}
			if !res.Match {
				return ExitInvalid
			}
			return ExitOK
		}
	},
}

var certificateBundle = &command{
	name:     "certificate bundle",
	summary:  "put certificates from several files into one ordered chain",
	synopsis: "smallca certificate bundle --cert FILE [--cert FILE ...] --fullchain-out FILE [--include-root]",
	desc: `Reads certificates from one or more files in any order, drops duplicates, and
writes them as one chain: the end certificate first, then each issuer. The
self-signed root is left out unless you give --include-root, because servers
should not send it.

It fails when the files hold more than one chain or certificates that do not
belong to the chain, rather than guessing. A chain whose root was not supplied
is written as far as it goes, with "ends_at_root": false.`,
	examples: `  # A CA sent the certificate and intermediates as separate files
  smallca certificate bundle --cert server.crt --cert intermediate2.crt --cert intermediate1.crt \
    --fullchain-out server-fullchain.pem`,
	output: `{"schema_version":1,"changed":true,"fullchain":"server-fullchain.pem",
 "chain":["CN=server.example.test","CN=Example Issuing CA"],"ends_at_root":true}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		var certs stringList
		fs.Var(&certs, "cert", "certificate `file`, PEM bundle, DER or PKCS#7 (repeatable)")
		out := fs.String(flagFullchainOut, "", "write the ordered chain to this `file`")
		root := fs.Bool("include-root", false, "keep the self-signed root at the end of the chain")
		return func(e *env) int {
			if rc := required(e, "cert", certs.String(), flagFullchainOut, *out); rc != cont {
				return rc
			}
			res, err := Bundle(certs, *out, *root)
			if err != nil {
				return fail(e, "bundle_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var certificateConvert = &command{
	name:     "certificate convert",
	summary:  "convert, split or repackage certificates and keys between PEM, DER, PKCS#7 and PKCS#12",
	synopsis: "smallca certificate convert --in FILE [--in FILE ...] [--format pem|der|p7b] OUTPUTS [" + passwordSynopsis + "]",
	desc: `Reads certificates and at most one private key from every --in file, in any
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
contents is kept.`,
	examples: `  # Split a .pfx into PEM files for nginx
  smallca certificate convert --in web.pfx --password-file pfx.pass \
    --cert-out web.crt --key-out web.key --chain-out chain.pem

  # One DER file per certificate in a PKCS#7 chain
  smallca certificate convert --in chain.p7b --split-dir certs --format der

  # PEM files to a .pfx for Windows
  smallca certificate convert --in web.crt --in web.key --in chain.pem \
    --p12-out web.pfx --password-file pfx.pass

  # A Java trust store of a root bundle
  smallca certificate convert --in roots.pem --truststore-out roots.p12 --password-file ts.pass`,
	output: `{"schema_version":1,"changed":true,"certificates":["CN=web.example.test","CN=Example Issuing CA"],"has_key":true}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		var in stringList
		fs.Var(&in, "in", "input `file`: PEM, DER, PKCS#7 or PKCS#12 (repeatable)")
		format := fs.String("format", "", "certificate output `format`: pem, der or p7b (default: from each file extension)")
		var o ConvertOptions
		fs.StringVar(&o.Out, "out", "", "write every certificate to this `file`")
		fs.StringVar(&o.CertOut, flagCertOut, "", "write the end certificate to this `file`")
		fs.StringVar(&o.ChainOut, flagChainOut, "", "write the issuers of the end certificate to this `file`")
		fs.StringVar(&o.FullchainOut, flagFullchainOut, "", "write the end certificate and its issuers to this `file`")
		fs.StringVar(&o.KeyOut, flagKeyOut, "", "write the private key, unencrypted, to this `file`")
		fs.StringVar(&o.SplitDir, "split-dir", "", "write each certificate to its own file in this `directory`")
		fs.StringVar(&o.P12Out, flagP12Out, "", "write a PKCS#12 file with the key and chain to this `file`")
		fs.StringVar(&o.TruststoreOut, "truststore-out", "", "write a PKCS#12 trust store of every certificate to this `file`")
		fs.BoolVar(&o.Legacy, "legacy", false, "use 3DES encryption for systems that cannot read AES-256 PKCS#12")
		getPass := passwordFlags(fs, false, "PKCS#12 or key")
		return func(e *env) int {
			if rc := required(e, "in", in.String()); rc != cont {
				return rc
			}
			if o.Out+o.CertOut+o.ChainOut+o.FullchainOut+o.KeyOut+o.SplitDir+o.P12Out+o.TruststoreOut == "" {
				return usageErr(e, "name at least one output: --out, --cert-out, --chain-out, --fullchain-out, "+
					"--key-out, --split-dir, --p12-out or --truststore-out")
			}
			pass, rc := getPass(e)
			if rc != cont {
				return rc
			}
			defer passphrase.Clear(pass)
			o.In, o.Format, o.Pass = in, *format, pass
			res, err := Convert(o)
			if err != nil {
				return fail(e, "convert_failed", err)
			}
			return writeJSON(e, res)
		}
	},
}

var mtlsVerify = &command{
	name:     "mtls verify",
	summary:  "check that a server and a client certificate trust each other for mutual TLS",
	synopsis: "smallca mtls verify --server-cert FILE --client-cert FILE --server-trust FILE --client-trust FILE [flags]\n  smallca mtls verify --url HOST[:PORT] --client-cert FILE --client-key FILE --client-trust FILE",
	desc: `Answers "will these two sides accept each other?" before you find out in a
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
all passed; exit code 3 means at least one failed.`,
	examples: `  # Before deploying: will the agent and the API accept each other?
  smallca mtls verify --server-cert api-fullchain.pem --server-key api.key \
    --server-trust clients-ca.pem --client-cert agent-fullchain.pem --client-key agent.key \
    --client-trust root.crt --host api.example.test

  # Against the running server
  smallca mtls verify --url api.example.test:8443 --client-cert agent-fullchain.pem \
    --client-key agent.key --client-trust root.crt`,
	output: `{"schema_version":1,"valid":false,"checks":[
 {"check":"client trusts server certificate","ok":true,"detail":"CN=api.example.test -> CN=Example Issuing CA -> CN=Example Root CA"},
 {"check":"server trusts client certificate","ok":false,"detail":"x509: certificate specifies an incompatible key usage"}]}`,
	setup: func(fs *flag.FlagSet) func(*env) int {
		serverCert := fs.String("server-cert", "", "server certificate `file`, intermediates after it")
		serverKey := fs.String("server-key", "", "server private key `file` (optional, checks it matches)")
		serverTrust := fs.String("server-trust", "", "CA certificates `file` the server trusts client certificates with")
		clientCert := fs.String("client-cert", "", "client certificate `file`, intermediates after it")
		clientKey := fs.String("client-key", "", "client private key `file` (needed with --url)")
		clientTrust := fs.String("client-trust", "", "CA certificates `file` the client trusts the server with")
		host := fs.String("host", "", "DNS `name` the client connects to (offline check)")
		target := fs.String("url", "", "test a live server: `host`, host:port or https://host:port")
		sni := fs.String("servername", "", "TLS server name (SNI) to send with --url (default: the host)")
		return func(e *env) int {
			load := func(path string) ([]*x509.Certificate, error) {
				if path == "" {
					return nil, nil
				}
				return readCerts(path)
			}
			var err error
			var server, client MTLSFiles
			client.Key, server.Key = *clientKey, *serverKey
			if client.Certs, err = load(*clientCert); err == nil {
				if client.Trust, err = load(*clientTrust); err == nil {
					if server.Certs, err = load(*serverCert); err == nil {
						server.Trust, err = load(*serverTrust)
					}
				}
			}
			if err != nil {
				return fail(e, "mtls_failed", err)
			}
			var res *MTLSResult
			if *target != "" {
				if rc := required(e, "client-cert", *clientCert, "client-key", *clientKey, "client-trust", *clientTrust); rc != cont {
					return rc
				}
				res = MTLSLive(context.Background(), *target, *sni, client)
			} else {
				if rc := required(e, "server-cert", *serverCert, "client-cert", *clientCert,
					"server-trust", *serverTrust, "client-trust", *clientTrust); rc != cont {
					return rc
				}
				res = MTLSOffline(server, client, *host)
			}
			if rc := writeJSON(e, res); rc != ExitOK {
				return rc
			}
			if !res.Valid {
				return ExitInvalid
			}
			return ExitOK
		}
	},
}

// leafNames returns the SANs for a new certificate or CSR: the subject common
// name first when it is a dotted host name, then each --san without duplicates.
func leafNames(e *env, subject string, sans []string) ([]string, []net.IP, int) {
	subj, err := ParseSubject(subject)
	if err != nil {
		return nil, nil, usageErr(e, "--subject: "+err.Error())
	}
	var all []string
	if strings.Contains(subj.CommonName, ".") && isHostname(subj.CommonName) {
		all = append(all, subj.CommonName)
	}
	for _, s := range sans {
		if !slices.Contains(all, s) {
			all = append(all, s)
		}
	}
	if len(all) == 0 {
		return nil, nil, usageErr(e, "no names: the subject common name is not a host name; give at least one --san")
	}
	dns, ips := splitSANs(all)
	return dns, ips, cont
}

// isHostname reports whether s is a DNS name (a leading "*." wildcard allowed)
// and not an IP address.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for i, label := range strings.Split(s, ".") {
		if i == 0 && label == "*" {
			continue
		}
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// splitSANs sorts --san values into DNS names and IP addresses.
func splitSANs(sans []string) ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	return dns, ips
}

// ---- help ----

const mainHelpTail = `Every command prints one JSON object on stdout ("schema_version":1), except
certificate inspect, which prints text unless given --json. Commands that write
files are idempotent: re-running one with the same inputs returns
"changed":false and rewrites nothing. An error is one JSON line on stderr:
  {"schema_version":1,"code":"...","message":"..."}

Exit codes: 0 ok, 1 error, 2 usage error, 3 certificate verify: not valid.

smallca never prompts. The root key password comes from --password-file,
--password-stdin or --password-fd.

Run 'smallca <command> --help' for a command's flags and examples.
`

func writeMainHelp(w io.Writer) {
	fmt.Fprintf(w, "smallca: non-interactive, idempotent certificate authority for automation\n\n")
	fmt.Fprintf(w, "USAGE\n  smallca <noun> <verb> [flags]\n\nCOMMANDS\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-21s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(w, "  %-21s %s\n  %-21s %s\n\n", "version", "print version and commit as JSON", "help [command]", "show help")
	fmt.Fprint(w, mainHelpTail)
}

// placeholders names flag values whose usage text has no `quoted` word.
var placeholders = map[string]string{
	"path-len": "n", "password-fd": "fd", "k8s-secret-name": "name", "k8s-secret-namespace": "namespace",
}

func writeHelp(w io.Writer, c *command) {
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	c.setup(fs)
	fs.Bool("quiet", false, "print nothing on stdout; rely on the exit code")
	fs.Bool("dry-run", false, "report what would change without writing any file")
	fmt.Fprintf(w, "NAME\n  smallca %s - %s\n\nUSAGE\n  %s\n\nDESCRIPTION\n", c.name, c.summary, c.synopsis)
	for _, l := range strings.Split(c.desc, "\n") {
		fmt.Fprintln(w, strings.TrimRight("  "+l, " "))
	}
	fmt.Fprintf(w, "\nFLAGS\n")
	var flags []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) { flags = append(flags, f) })
	for _, f := range flags {
		name, usage := flag.UnquoteUsage(f)
		if alt, ok := placeholders[f.Name]; ok {
			name = alt
		}
		line := "  --" + f.Name
		if name != "" {
			line += " " + strings.ToUpper(name)
		}
		fmt.Fprintln(w, line)
		if f.DefValue != "" && f.DefValue != "0" && f.DefValue != "false" {
			usage += " (default " + f.DefValue + ")"
		}
		fmt.Fprintf(w, "      %s\n", usage)
	}
	fmt.Fprintf(w, "\nEXAMPLES\n%s\n\nOUTPUT\n", c.examples)
	for _, l := range strings.Split(c.output, "\n") {
		fmt.Fprintln(w, "  "+l)
	}
	fmt.Fprintf(w, "\nEXIT CODES\n  0 ok, 1 error, 2 usage error")
	if c == certificateVerify {
		fmt.Fprint(w, ", 3 chain does not verify")
	}
	fmt.Fprintln(w)
}
