// Package smallca is a non-interactive, idempotent certificate authority for
// automation: it creates a root, signs an externally generated
// subordinate-CA CSR (for example FreeIPA's /root/ipa.csr), creates
// intermediates whose key it generates itself, issues leaf certificates from
// such an intermediate, and verifies chains.
//
// smallca keeps no database: its idempotency comes from inspecting the files it
// already wrote. Profiles are explicit flags with safe defaults.
package smallca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.step.sm/crypto/pemutil"

	"github.com/newen-systems/smallca/internal/certfmt"
	"github.com/newen-systems/smallca/internal/csrutil"
	"github.com/newen-systems/smallca/internal/dn"
)

// backdate tolerates clock skew between smallca and relying parties.
const backdate = 5 * time.Minute

// renewWithin is the longest renewal window: a re-run replaces a certificate
// that expires within 30 days, or within the last third of its lifetime if
// that is shorter, so short-lived certificates are not re-issued on every run.
const renewWithin = 30 * 24 * time.Hour

// renewWindow returns the renewal window for c.
func renewWindow(c *x509.Certificate) time.Duration {
	return min(renewWithin, c.NotAfter.Sub(c.NotBefore)/3)
}

const (
	rootCertName = "root.crt"
	rootKeyName  = "root.key"
)

// now is the package clock; tests override it.
var now = time.Now

// dryRun makes every write a no-op that still reports whether it would have
// changed the file (--dry-run, Ansible check mode).
var dryRun bool

// Root is the loaded root CA.
type Root struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// ParseDuration accepts Go duration syntax plus whole-number "d" (days) and "y"
// (365-day years) suffixes, and rejects non-positive values.
func ParseDuration(s string) (time.Duration, error) {
	unit := time.Duration(0)
	num := s
	switch {
	case strings.HasSuffix(s, "y"):
		unit, num = 365*24*time.Hour, strings.TrimSuffix(s, "y")
	case strings.HasSuffix(s, "d"):
		unit, num = 24*time.Hour, strings.TrimSuffix(s, "d")
	}
	var d time.Duration
	if unit != 0 {
		n, err := strconv.Atoi(num)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		if n > int(math.MaxInt64/int64(unit)) {
			return 0, fmt.Errorf("duration %q is too long", s)
		}
		d = time.Duration(n) * unit
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// ParseNotAfter accepts an RFC 3339 time or a duration (see ParseDuration)
// and returns the validity it means from now.
func ParseNotAfter(s string) (time.Duration, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		d := t.Sub(now())
		if d <= 0 {
			return 0, fmt.Errorf("not-after %q is in the past", s)
		}
		return d, nil
	}
	return ParseDuration(s)
}

// KeySpec names a key to generate, in the step CLI's terms: Kty is EC or RSA,
// Crv is P-256 or P-384 for EC, Size is 2048, 3072 or 4096 for RSA.
type KeySpec struct {
	Kty  string
	Crv  string
	Size int
}

// Resolve validates s and fills the defaults: defCrv for EC, 3072 bits for RSA.
func (s KeySpec) Resolve(defCrv string) (KeySpec, error) {
	switch strings.ToUpper(s.Kty) {
	case "EC", "":
		if s.Size != 0 {
			return s, errors.New("--size applies to --kty RSA only")
		}
		s.Kty = "EC"
		if s.Crv == "" {
			s.Crv = defCrv
		}
		if s.Crv != "P-256" && s.Crv != "P-384" {
			return s, fmt.Errorf("unsupported --crv %q, want P-256 or P-384", s.Crv)
		}
	case "RSA":
		if s.Crv != "" {
			return s, errors.New("--crv applies to --kty EC only")
		}
		s.Kty = "RSA"
		if s.Size == 0 {
			s.Size = 3072
		}
		if s.Size != 2048 && s.Size != 3072 && s.Size != 4096 {
			return s, fmt.Errorf("unsupported --size %d, want 2048, 3072 or 4096", s.Size)
		}
	default:
		return s, fmt.Errorf("unsupported --kty %q, want EC or RSA", s.Kty)
	}
	return s, nil
}

// Generate creates a key for a resolved spec.
func (s KeySpec) Generate() (crypto.Signer, error) {
	switch {
	case s.Kty == "EC" && s.Crv == "P-256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case s.Kty == "EC" && s.Crv == "P-384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case s.Kty == "RSA":
		return rsa.GenerateKey(rand.Reader, s.Size)
	}
	return nil, fmt.Errorf("key spec %+v not resolved", s)
}

// Fingerprint is the SHA-256 of the certificate DER, "sha256:<hex>".
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newSerial returns a positive random serial with 128 bits of entropy. SetBytes
// is unsigned and encoding/asn1 adds a 0x00 octet when the high bit is set, so
// the DER is at most 17 octets, inside the 20-octet limit.
func newSerial() (*big.Int, error) {
	b := make([]byte, 16)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if s := new(big.Int).SetBytes(b); s.Sign() > 0 {
			return s, nil
		}
	}
}

// ParseSubject parses a distinguished name such as "CN=Lab Root,O=Example". A
// value without "=" is taken as a bare common name, as the step CLI does.
func ParseSubject(s string) (pkix.Name, error) {
	if !strings.Contains(s, "=") {
		if strings.TrimSpace(s) == "" {
			return pkix.Name{}, errors.New("empty subject")
		}
		return pkix.Name{CommonName: s}, nil
	}
	return dn.ParseDN(s)
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func plainKeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// readCert reads a file holding exactly one certificate.
func readCert(path string) (*x509.Certificate, error) {
	certs, err := readCerts(path)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%s: holds %d certificates, want 1", path, len(certs))
	}
	return certs[0], nil
}

func readCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator names every input file
	if err != nil {
		return nil, err
	}
	return parseCerts(path, b)
}

// parseCerts decodes every certificate in b; name labels errors.
func parseCerts(path string, b []byte) ([]*x509.Certificate, error) {
	ders, err := certfmt.DecodeCerts(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// readKey reads a PEM private key (PKCS#8, PKCS#1 or SEC1), decrypting it
// with pass when pass is not nil.
func readKey(path string, pass []byte) (crypto.Signer, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator names every input file
	if err != nil {
		return nil, err
	}
	return parseKey(path, b, pass)
}

// KeyEncrypted reports whether PEM key material is password protected.
func KeyEncrypted(b []byte) bool {
	return bytes.Contains(b, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) ||
		bytes.Contains(b, []byte("Proc-Type: 4,ENCRYPTED"))
}

// parseKey parses PEM key material; name labels errors.
func parseKey(path string, b, pass []byte) (crypto.Signer, error) {
	var opts []pemutil.Options
	if pass != nil {
		opts = append(opts, pemutil.WithPassword(pass))
	}
	k, err := pemutil.Parse(b, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: key type %T cannot sign", path, k)
	}
	return s, nil
}

func keyMatches(k crypto.Signer, c *x509.Certificate) bool {
	return pubEqual(k.Public(), c.PublicKey)
}

func pubEqual(a, b crypto.PublicKey) bool {
	p, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && p.Equal(b)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeIfChanged writes data atomically with mode unless the file already holds
// exactly data. It reports whether it wrote.
func writeIfChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) { // #nosec G304 -- the operator names every output file
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".smallca-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

type outFile struct {
	path string
	data []byte
	mode os.FileMode
}

// writeAll writes each named file that changed and reports whether any did.
func writeAll(files ...outFile) (bool, error) {
	changed := false
	for _, f := range files {
		if f.path == "" {
			continue
		}
		w, err := writeIfChanged(f.path, f.data, f.mode)
		if err != nil {
			return changed, err
		}
		changed = changed || w
	}
	return changed, nil
}

// caTemplate is the CA profile shared by the root, signed CSRs and generated
// intermediates: CA:TRUE (critical), the given path length (negative means
// unconstrained), keyUsage keyCertSign|cRLSign (critical), and optional
// critical DNS name constraints. The shape is adapted from the
// smallstep/certificates v0.30.2 intermediate profile (Apache-2.0); see NOTICE.
func caTemplate(pathLen int, permittedDNS []string, notAfter time.Time) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now().Add(-backdate),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if pathLen < 0 {
		t.MaxPathLen = -1
	}
	if len(permittedDNS) > 0 {
		t.PermittedDNSDomains = permittedDNS
		t.PermittedDNSDomainsCritical = true
	}
	return t, nil
}

// childNotAfter caps now+validity at the issuer's own expiry.
func childNotAfter(parent *x509.Certificate, validity time.Duration) (time.Time, error) {
	if !parent.NotAfter.After(now()) {
		return time.Time{}, errors.New("issuer certificate has expired")
	}
	na := now().Add(validity)
	if na.After(parent.NotAfter) {
		na = parent.NotAfter
	}
	return na, nil
}

// checkPathLen rejects a child CA whose path length the parent cannot allow.
func checkPathLen(parent *x509.Certificate, pathLen int) error {
	if parent.MaxPathLen < 0 && !parent.MaxPathLenZero {
		return nil // parent is unconstrained
	}
	if pathLen < 0 || pathLen >= parent.MaxPathLen {
		return fmt.Errorf("child path length %d must be between 0 and %d (issuer path length %d)",
			pathLen, parent.MaxPathLen-1, parent.MaxPathLen)
	}
	return nil
}

// sameCAProfile reports whether an existing CA cert carries the requested
// path length and name constraints, so a changed flag forces a re-sign.
func sameCAProfile(c *x509.Certificate, pathLen int, permittedDNS []string) bool {
	got := c.MaxPathLen
	if got == 0 && !c.MaxPathLenZero {
		got = -1
	}
	want := pathLen
	if want < 0 {
		want = -1
	}
	return c.IsCA && got == want && slices.Equal(c.PermittedDNSDomains, permittedDNS)
}

// fresh reports whether c chains to parent and is outside its renewal window.
func fresh(c, parent *x509.Certificate) bool {
	return c.CheckSignatureFrom(parent) == nil && c.NotAfter.After(now().Add(renewWindow(c)))
}

// verifyOne checks c against a pool of roots, with optional intermediates, at
// the package clock.
func verifyOne(c *x509.Certificate, roots, inter []*x509.Certificate, dnsName string) ([][]*x509.Certificate, error) {
	rp := x509.NewCertPool()
	for _, r := range roots {
		rp.AddCert(r)
	}
	ip := x509.NewCertPool()
	for _, i := range inter {
		ip.AddCert(i)
	}
	return c.Verify(x509.VerifyOptions{
		Roots:         rp,
		Intermediates: ip,
		DNSName:       dnsName,
		CurrentTime:   now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
}

// certInfo is the description of an issued certificate shared by every result.
type certInfo struct {
	Subject     string `json:"subject"`
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint_sha256"`
	NotAfter    string `json:"not_after"`
}

func describe(c *x509.Certificate) certInfo {
	return certInfo{
		Subject:     c.Subject.String(),
		Serial:      c.SerialNumber.String(),
		Fingerprint: Fingerprint(c),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
	}
}

// ---- root create ----

// RootResult is the JSON output of root create.
type RootResult struct {
	Changed  bool   `json:"changed"`
	RootCert string `json:"root_cert"`
	RootKey  string `json:"root_key"`
	certInfo
}

// RootOptions are the root create inputs.
type RootOptions struct {
	Dir      string
	Subject  string
	Key      KeySpec // resolved
	Validity time.Duration
	PathLen  int
}

// CreateRoot creates the root in dir, or loads and checks an existing one. It
// never overwrites an existing root, and it fails if the existing root's
// subject differs from the one requested.
func CreateRoot(o RootOptions, pass []byte) (*RootResult, error) {
	certPath, keyPath := filepath.Join(o.Dir, rootCertName), filepath.Join(o.Dir, rootKeyName)
	subject, err := ParseSubject(o.Subject)
	if err != nil {
		return nil, err
	}
	res := &RootResult{RootCert: certPath, RootKey: keyPath}
	if exists(certPath) || exists(keyPath) {
		root, err := LoadRoot(o.Dir, pass)
		if err != nil {
			return nil, fmt.Errorf("existing root: %w", err)
		}
		if root.Cert.Subject.String() != subject.String() {
			return nil, fmt.Errorf("existing root subject %q differs from requested %q", root.Cert.Subject, subject)
		}
		res.certInfo = describe(root.Cert)
		return res, nil
	}
	if !dryRun {
		if err := os.MkdirAll(o.Dir, 0o700); err != nil {
			return nil, err
		}
	}
	key, err := o.Key.Generate()
	if err != nil {
		return nil, err
	}
	tpl, err := caTemplate(o.PathLen, nil, now().Add(o.Validity))
	if err != nil {
		return nil, err
	}
	tpl.Subject = subject
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	block, err := pemutil.Serialize(key, pemutil.WithPassword(pass), pemutil.WithPKCS8(true))
	if err != nil {
		return nil, err
	}
	// Key first: a cert without its key is unusable, a key without its cert is
	// detected by LoadRoot on the next run.
	if _, err := writeAll(outFile{keyPath, pem.EncodeToMemory(block), 0o600}, outFile{certPath, certPEM(cert), 0o644}); err != nil {
		return nil, err
	}
	res.Changed = true
	res.certInfo = describe(cert)
	return res, nil
}

// RootPaths returns the root certificate and key paths inside dir.
func RootPaths(dir string) (cert, key string) {
	return filepath.Join(dir, rootCertName), filepath.Join(dir, rootKeyName)
}

// LoadRoot loads dir/root.crt and the encrypted dir/root.key.
func LoadRoot(dir string, pass []byte) (*Root, error) {
	certPath, keyPath := RootPaths(dir)
	certPEM, err := os.ReadFile(certPath) // #nosec G304 -- the operator names the directory
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- the operator names the directory
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	return ParseRoot(certPEM, keyPEM, pass)
}

// ParseRoot checks the certificate is one CA with certSign usage and that the
// key (decrypted with pass when pass is not nil) matches it. Taking bytes lets
// the root come from a pipe or a secret manager without touching disk.
func ParseRoot(certPEM, keyPEM, pass []byte) (*Root, error) {
	certs, err := parseCerts("root certificate", certPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("root certificate: holds %d certificates, want 1", len(certs))
	}
	cert := certs[0]
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("root certificate is not a CA with certSign usage")
	}
	key, err := parseKey("root key", keyPEM, pass)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	if !keyMatches(key, cert) {
		return nil, errors.New("root key does not match root certificate")
	}
	return &Root{Cert: cert, Key: key}, nil
}

// ---- intermediate sign ----

// SignResult is the JSON output of intermediate sign.
type SignResult struct {
	Changed         bool   `json:"changed"`
	Cert            string `json:"cert"`
	Chain           string `json:"chain,omitempty"`
	Fullchain       string `json:"fullchain,omitempty"`
	RootFingerprint string `json:"root_fingerprint_sha256"`
	certInfo
}

// SignOptions are the intermediate sign inputs.
type SignOptions struct {
	CSRPath      string
	CertOut      string
	ChainOut     string
	FullchainOut string
	Validity     time.Duration
	PathLen      int
	PermittedDNS []string
}

// SignCSR signs a subordinate-CA CSR with the root. The subject is copied
// byte-for-byte from the CSR (FreeIPA compares the DER). CSR extensions are
// never copied. An existing CertOut for the same key, subject and profile,
// signed by this root and not near expiry, is kept.
func SignCSR(root *Root, o SignOptions) (*SignResult, error) {
	csrBytes, err := os.ReadFile(o.CSRPath)
	if err != nil {
		return nil, err
	}
	csr, err := csrutil.ParseCSR(csrBytes)
	if err != nil {
		return nil, err
	}
	if err := checkPathLen(root.Cert, o.PathLen); err != nil {
		return nil, err
	}
	res := &SignResult{Cert: o.CertOut, Chain: o.ChainOut, Fullchain: o.FullchainOut,
		RootFingerprint: Fingerprint(root.Cert)}

	var cert *x509.Certificate
	if old, err := readCert(o.CertOut); err == nil &&
		bytes.Equal(old.RawSubject, csr.RawSubject) && pubEqual(old.PublicKey, csr.PublicKey) &&
		sameCAProfile(old, o.PathLen, o.PermittedDNS) && fresh(old, root.Cert) {
		cert = old
	} else {
		notAfter, err := childNotAfter(root.Cert, o.Validity)
		if err != nil {
			return nil, err
		}
		tpl, err := caTemplate(o.PathLen, o.PermittedDNS, notAfter)
		if err != nil {
			return nil, err
		}
		tpl.RawSubject = csr.RawSubject
		der, err := x509.CreateCertificate(rand.Reader, tpl, root.Cert, csr.PublicKey, root.Key)
		if err != nil {
			return nil, err
		}
		if cert, err = x509.ParseCertificate(der); err != nil {
			return nil, err
		}
		if !bytes.Equal(cert.RawSubject, csr.RawSubject) {
			return nil, errors.New("self-check: issued subject DER differs from CSR subject DER")
		}
		if _, err := verifyOne(cert, []*x509.Certificate{root.Cert}, nil, ""); err != nil {
			return nil, fmt.Errorf("self-check: %w", err)
		}
	}
	res.Changed, err = writeAll(
		outFile{o.CertOut, certPEM(cert), 0o644},
		outFile{o.ChainOut, certPEM(root.Cert), 0o644},
		outFile{o.FullchainOut, append(certPEM(cert), certPEM(root.Cert)...), 0o644},
	)
	if err != nil {
		return nil, err
	}
	res.certInfo = describe(cert)
	return res, nil
}

// ---- intermediate create ----

// IntermediateResult is the JSON output of intermediate create.
type IntermediateResult struct {
	Changed   bool   `json:"changed"`
	Key       string `json:"key"`
	Cert      string `json:"cert"`
	Chain     string `json:"chain,omitempty"`
	Fullchain string `json:"fullchain,omitempty"`
	Secret    string `json:"k8s_secret,omitempty"`
	certInfo
}

// IntermediateOptions are the intermediate create inputs.
type IntermediateOptions struct {
	Subject      string
	CertOut      string
	KeyOut       string
	ChainOut     string
	FullchainOut string
	Key          KeySpec // resolved
	Validity     time.Duration
	PathLen      int
	PermittedDNS []string
	SecretOut    string
	SecretName   string
	SecretNS     string
}

// Intermediate creates a key and a root-signed CA cert for it, or keeps an
// existing valid pair. An existing pair that does not check out is an error:
// smallca never silently replaces a CA key that something may already trust.
func Intermediate(root *Root, o IntermediateOptions) (*IntermediateResult, error) {
	subject, err := ParseSubject(o.Subject)
	if err != nil {
		return nil, err
	}
	if err := checkPathLen(root.Cert, o.PathLen); err != nil {
		return nil, err
	}
	if (o.SecretOut == "") != (o.SecretName == "") {
		return nil, errors.New("--k8s-secret-out and --k8s-secret-name go together")
	}
	res := &IntermediateResult{Key: o.KeyOut, Cert: o.CertOut, Chain: o.ChainOut, Fullchain: o.FullchainOut, Secret: o.SecretOut}

	var key crypto.Signer
	var cert *x509.Certificate
	if exists(o.KeyOut) || exists(o.CertOut) {
		if key, err = readKey(o.KeyOut, nil); err != nil {
			return nil, fmt.Errorf("existing intermediate: %w", err)
		}
		if cert, err = readCert(o.CertOut); err != nil {
			return nil, fmt.Errorf("existing intermediate: %w", err)
		}
		switch {
		case !keyMatches(key, cert):
			return nil, errors.New("existing intermediate: key does not match certificate")
		case cert.Subject.String() != subject.String():
			return nil, fmt.Errorf("existing intermediate: subject %q differs from requested %q", cert.Subject, subject)
		case !sameCAProfile(cert, o.PathLen, o.PermittedDNS):
			return nil, errors.New("existing intermediate: path length or name constraints differ from requested")
		case !fresh(cert, root.Cert):
			return nil, errors.New("existing intermediate: not signed by this root or inside its renewal window; move it aside to re-issue")
		}
	} else {
		if key, err = o.Key.Generate(); err != nil {
			return nil, err
		}
		notAfter, err := childNotAfter(root.Cert, o.Validity)
		if err != nil {
			return nil, err
		}
		tpl, err := caTemplate(o.PathLen, o.PermittedDNS, notAfter)
		if err != nil {
			return nil, err
		}
		tpl.Subject = subject
		der, err := x509.CreateCertificate(rand.Reader, tpl, root.Cert, key.Public(), root.Key)
		if err != nil {
			return nil, err
		}
		if cert, err = x509.ParseCertificate(der); err != nil {
			return nil, err
		}
	}
	keyPEM, err := plainKeyPEM(key)
	if err != nil {
		return nil, err
	}
	files := []outFile{
		// An existing key is rewritten only if its encoding differs; the
		// key material itself is never replaced.
		{o.KeyOut, keyPEM, 0o600},
		{o.CertOut, certPEM(cert), 0o644},
		{o.ChainOut, certPEM(root.Cert), 0o644},
		{o.FullchainOut, append(certPEM(cert), certPEM(root.Cert)...), 0o644},
	}
	if o.SecretOut != "" {
		files = append(files, outFile{o.SecretOut, TLSSecretYAML(o.SecretName, o.SecretNS, certPEM(cert), keyPEM, certPEM(root.Cert)), 0o600})
	}
	if exists(o.KeyOut) {
		files = files[1:] // keep the operator's key file byte-for-byte
	}
	if res.Changed, err = writeAll(files...); err != nil {
		return nil, err
	}
	res.certInfo = describe(cert)
	return res, nil
}

// TLSSecretYAML renders a kubernetes.io/tls Secret in the shape cert-manager's
// CA issuer reads: tls.crt (the CA cert), tls.key, and ca.crt (the root).
func TLSSecretYAML(name, namespace string, crt, key, ca []byte) []byte {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + strconv.Quote(name) + "\n")
	if namespace != "" {
		b.WriteString("  namespace: " + strconv.Quote(namespace) + "\n")
	}
	b.WriteString("type: kubernetes.io/tls\ndata:\n")
	b.WriteString("  tls.crt: " + b64(crt) + "\n")
	b.WriteString("  tls.key: " + b64(key) + "\n")
	b.WriteString("  ca.crt: " + b64(ca) + "\n")
	return []byte(b.String())
}

// ---- leaf create ----

// LeafResult is the JSON output of leaf create.
type LeafResult struct {
	Changed     bool     `json:"changed"`
	Key         string   `json:"key"`
	Cert        string   `json:"cert"`
	Chain       string   `json:"chain,omitempty"`
	Fullchain   string   `json:"fullchain,omitempty"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	certInfo
}

// LeafOptions are the leaf create inputs.
type LeafOptions struct {
	CACert       string
	CAKey        string
	Subject      string
	DNS          []string
	IPs          []net.IP
	CertOut      string
	KeyOut       string
	ChainOut     string
	FullchainOut string
	Validity     time.Duration
	Key          KeySpec // resolved
	Purpose      string  // server, client or both
}

// Leaf issues an end-entity certificate from an intermediate whose key smallca
// holds in clear. The key at KeyOut is reused when present.
func Leaf(o LeafOptions) (*LeafResult, error) {
	subject, err := ParseSubject(o.Subject)
	if err != nil {
		return nil, err
	}
	rawSubject, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	caCert, caKey, err := loadIssuer(o.CACert, o.CAKey)
	if err != nil {
		return nil, err
	}
	var files []outFile
	var key crypto.Signer
	if exists(o.KeyOut) {
		if key, err = readKey(o.KeyOut, nil); err != nil {
			return nil, err
		}
	} else {
		if key, err = o.Key.Generate(); err != nil {
			return nil, err
		}
		keyPEM, err := plainKeyPEM(key)
		if err != nil {
			return nil, err
		}
		files = append(files, outFile{o.KeyOut, keyPEM, 0o600})
	}
	eku, err := PurposeEKU(o.Purpose)
	if err != nil {
		return nil, err
	}
	var cert *x509.Certificate
	if old, err := readCert(o.CertOut); err == nil && sameLeaf(old, caCert, key.Public(), rawSubject, o.DNS, o.IPs, eku) {
		cert = old
	} else if cert, err = issueLeaf(caCert, caKey, key.Public(), rawSubject, o.DNS, o.IPs, eku, o.Validity); err != nil {
		return nil, err
	}
	files = append(files,
		outFile{o.CertOut, certPEM(cert), 0o644},
		outFile{o.ChainOut, certPEM(caCert), 0o644},
		outFile{o.FullchainOut, append(certPEM(cert), certPEM(caCert)...), 0o644},
	)
	res := &LeafResult{Key: o.KeyOut, Cert: o.CertOut, Chain: o.ChainOut, Fullchain: o.FullchainOut}
	if res.Changed, err = writeAll(files...); err != nil {
		return nil, err
	}
	fillLeaf(res, cert)
	return res, nil
}

func ipsEqual(a, b []net.IP) bool {
	return slices.EqualFunc(a, b, func(x, y net.IP) bool { return x.Equal(y) })
}

// ---- certificate verify ----

// VerifyResult is the JSON output of certificate verify.
type VerifyResult struct {
	Valid       bool     `json:"valid"`
	Error       string   `json:"error,omitempty"`
	Subject     string   `json:"subject"`
	Fingerprint string   `json:"fingerprint_sha256"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	Chain       []string `json:"chain,omitempty"`
}

// Verify checks certs[0] against roots (when roots is not empty), using the
// rest of certs and inter as intermediates, and, when minRemaining > 0, that
// it stays valid for at least that long.
func Verify(roots, certs, inter []*x509.Certificate, host string, minRemaining time.Duration) *VerifyResult {
	leaf := certs[0]
	inter = append(append([]*x509.Certificate{}, certs[1:]...), inter...)
	left := leaf.NotAfter.Sub(now())
	res := &VerifyResult{Subject: leaf.Subject.String(), Fingerprint: Fingerprint(leaf),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), DaysLeft: int(left.Hours() / 24)}
	if len(roots) > 0 {
		chains, err := verifyOne(leaf, roots, inter, host)
		if err != nil {
			res.Error = err.Error()
			return res
		}
		for _, c := range chains[0] {
			res.Chain = append(res.Chain, c.Subject.String())
		}
	} else if host != "" {
		if err := leaf.VerifyHostname(host); err != nil {
			res.Error = err.Error()
			return res
		}
	}
	if minRemaining > 0 && left < minRemaining {
		res.Error = fmt.Sprintf("expires in %s, less than the required %s", left.Round(time.Minute), minRemaining)
		return res
	}
	res.Valid = true
	return res
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
