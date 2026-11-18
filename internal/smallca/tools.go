package smallca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/newen-systems/smallca/internal/certfmt"
	"github.com/newen-systems/smallca/internal/csrutil"
)

// ---- shared leaf issuance ----

// loadIssuer reads an intermediate whose key smallca holds in clear and checks
// it may issue leaves.
func loadIssuer(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	caCert, err := readCert(certPath)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := readKey(keyPath, nil)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case !keyMatches(caKey, caCert):
		return nil, nil, errors.New("CA key does not match CA certificate")
	case !caCert.IsCA || caCert.KeyUsage&x509.KeyUsageCertSign == 0:
		return nil, nil, errors.New("CA certificate is not a CA with certSign usage")
	case caCert.CheckSignatureFrom(caCert) == nil:
		return nil, nil, errors.New("refusing to issue a leaf directly from a self-signed root; create an intermediate first")
	}
	return caCert, caKey, nil
}

// Purposes accepted by --purpose.
var purposes = map[string][]x509.ExtKeyUsage{
	"server": {x509.ExtKeyUsageServerAuth},
	"client": {x509.ExtKeyUsageClientAuth},
	"both":   {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
}

// PurposeEKU returns the extended key usages for --purpose.
func PurposeEKU(purpose string) ([]x509.ExtKeyUsage, error) {
	if eku, ok := purposes[purpose]; ok {
		return eku, nil
	}
	return nil, fmt.Errorf("unsupported --purpose %q, want server, client or both", purpose)
}

// sameLeaf reports whether old already is the certificate a request asks for.
func sameLeaf(old, caCert *x509.Certificate, pub crypto.PublicKey, rawSubject []byte, dns []string, ips []net.IP, eku []x509.ExtKeyUsage) bool {
	return pubEqual(old.PublicKey, pub) && bytes.Equal(old.RawSubject, rawSubject) &&
		slices.Equal(old.DNSNames, dns) && ipsEqual(old.IPAddresses, ips) &&
		slices.Equal(old.ExtKeyUsage, eku) && fresh(old, caCert)
}

// issueLeaf signs an end-entity certificate for pub. rawSubject is DER.
func issueLeaf(caCert *x509.Certificate, caKey crypto.Signer, pub crypto.PublicKey, rawSubject []byte,
	dns []string, ips []net.IP, eku []x509.ExtKeyUsage, validity time.Duration) (*x509.Certificate, error) {
	notAfter, err := childNotAfter(caCert, validity)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	ku := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		ku |= x509.KeyUsageKeyEncipherment
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            rawSubject,
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             now().Add(-backdate),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, pub, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ---- leaf sign ----

// LeafSignOptions are the leaf sign inputs.
type LeafSignOptions struct {
	CACert       string
	CAKey        string
	CSRPath      string
	DNS          []string // replace the CSR's SANs when DNS or IPs is set
	IPs          []net.IP
	CertOut      string
	ChainOut     string
	FullchainOut string
	Validity     time.Duration
	Purpose      string
}

// LeafSign signs an end-entity CSR generated elsewhere (an appliance, a Java
// keystore, a service). Only the subject and public key come from the CSR;
// key usages are set here, and SANs come from the CSR unless overridden.
func LeafSign(o LeafSignOptions) (*LeafResult, error) {
	caCert, caKey, err := loadIssuer(o.CACert, o.CAKey)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(o.CSRPath)
	if err != nil {
		return nil, err
	}
	csr, err := csrutil.ParseCSR(b)
	if err != nil {
		return nil, err
	}
	dns, ips := o.DNS, o.IPs
	if len(dns) == 0 && len(ips) == 0 {
		dns, ips = csr.DNSNames, csr.IPAddresses
	}
	if len(dns) == 0 && len(ips) == 0 {
		if csr.Subject.CommonName == "" {
			return nil, errors.New("the CSR has no SANs and no common name; give --san")
		}
		dns = []string{csr.Subject.CommonName}
	}
	eku, err := PurposeEKU(o.Purpose)
	if err != nil {
		return nil, err
	}
	var cert *x509.Certificate
	if old, err := readCert(o.CertOut); err == nil && sameLeaf(old, caCert, csr.PublicKey, csr.RawSubject, dns, ips, eku) {
		cert = old
	} else if cert, err = issueLeaf(caCert, caKey, csr.PublicKey, csr.RawSubject, dns, ips, eku, o.Validity); err != nil {
		return nil, err
	}
	res := &LeafResult{Cert: o.CertOut, Chain: o.ChainOut, Fullchain: o.FullchainOut}
	if res.Changed, err = writeAll(
		outFile{o.CertOut, certPEM(cert), 0o644},
		outFile{o.ChainOut, certPEM(caCert), 0o644},
		outFile{o.FullchainOut, append(certPEM(cert), certPEM(caCert)...), 0o644},
	); err != nil {
		return nil, err
	}
	fillLeaf(res, cert)
	return res, nil
}

func fillLeaf(res *LeafResult, cert *x509.Certificate) {
	res.DNSNames = cert.DNSNames
	res.IPAddresses = nil
	for _, ip := range cert.IPAddresses {
		res.IPAddresses = append(res.IPAddresses, ip.String())
	}
	res.certInfo = describe(cert)
}

// ---- csr create ----

// CSRResult is the JSON output of csr create.
type CSRResult struct {
	Changed     bool     `json:"changed"`
	Key         string   `json:"key"`
	CSR         string   `json:"csr"`
	Subject     string   `json:"subject"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
}

// CSROptions are the csr create inputs.
type CSROptions struct {
	Subject string
	DNS     []string
	IPs     []net.IP
	KeyOut  string
	CSROut  string
	Key     KeySpec // resolved
}

// CreateCSR writes a key (reused when present) and a CSR for it, for a CA
// that smallca does not run. An existing CSR for the same key, subject and
// SANs is kept even though a re-signed one would differ byte for byte.
func CreateCSR(o CSROptions) (*CSRResult, error) {
	subject, err := ParseSubject(o.Subject)
	if err != nil {
		return nil, err
	}
	res := &CSRResult{Key: o.KeyOut, CSR: o.CSROut, Subject: subject.String(), DNSNames: o.DNS}
	for _, ip := range o.IPs {
		res.IPAddresses = append(res.IPAddresses, ip.String())
	}
	var key crypto.Signer
	var files []outFile
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
	if old, err := os.ReadFile(o.CSROut); err == nil { // #nosec G304 -- the operator names every output file
		if csr, err := csrutil.ParseCSR(old); err == nil && pubEqual(csr.PublicKey, key.Public()) &&
			csr.Subject.String() == subject.String() && slices.Equal(csr.DNSNames, o.DNS) && ipsEqual(csr.IPAddresses, o.IPs) {
			res.Changed, err = writeAll(files...)
			return res, err
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: o.DNS, IPAddresses: o.IPs,
	}, key)
	if err != nil {
		return nil, err
	}
	files = append(files, outFile{o.CSROut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644})
	if res.Changed, err = writeAll(files...); err != nil {
		return nil, err
	}
	return res, nil
}

// ---- certificate match ----

// MatchResult is the JSON output of certificate match.
type MatchResult struct {
	Match    bool              `json:"match"`
	Keys     map[string]string `json:"public_keys"`
	Mismatch string            `json:"mismatch,omitempty"`
}

// Match reports whether a certificate, a private key and a CSR (any two or
// more) carry the same public key. pass decrypts an encrypted key.
func Match(certPath, keyPath, csrPath string, pass []byte) (*MatchResult, error) {
	type item struct {
		name string
		pub  crypto.PublicKey
	}
	var items []item
	if certPath != "" {
		c, err := readCerts(certPath)
		if err != nil {
			return nil, err
		}
		items = append(items, item{"cert", c[0].PublicKey})
	}
	if keyPath != "" {
		k, err := readKey(keyPath, pass)
		if err != nil {
			return nil, err
		}
		items = append(items, item{"key", k.Public()})
	}
	if csrPath != "" {
		b, err := os.ReadFile(csrPath) // #nosec G304
		if err != nil {
			return nil, err
		}
		csr, err := parseAnyCSR(b)
		if err != nil {
			return nil, err
		}
		items = append(items, item{"csr", csr.PublicKey})
	}
	if len(items) < 2 {
		return nil, errors.New("give at least two of --cert, --key and --csr")
	}
	res := &MatchResult{Match: true, Keys: map[string]string{}}
	for _, it := range items {
		res.Keys[it.name] = pubFingerprint(it.pub)
		if !pubEqual(items[0].pub, it.pub) && res.Match {
			res.Match = false
			res.Mismatch = fmt.Sprintf("%s and %s hold different public keys", items[0].name, it.name)
		}
	}
	return res, nil
}

// ---- certificate bundle ----

// BundleResult is the JSON output of certificate bundle.
type BundleResult struct {
	Changed   bool     `json:"changed"`
	Fullchain string   `json:"fullchain"`
	Chain     []string `json:"chain"`
	Complete  bool     `json:"ends_at_root"`
}

// Bundle orders the certificates found in files into one chain, leaf first,
// dropping duplicates and, unless includeRoot, the self-signed root. It
// fails when the input holds more than one chain or certificates that do not
// belong to the chain.
func Bundle(files []string, out string, includeRoot bool) (*BundleResult, error) {
	var all []*x509.Certificate
	for _, f := range files {
		cs, err := readCerts(f)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if !slices.ContainsFunc(all, func(x *x509.Certificate) bool { return bytes.Equal(x.Raw, c.Raw) }) {
				all = append(all, c)
			}
		}
	}
	leaves := endCerts(all)
	if len(leaves) != 1 {
		return nil, fmt.Errorf("found %d end certificates, want exactly 1: the input holds more than one chain", len(leaves))
	}
	chain, err := orderChain(leaves[0], all)
	if err != nil {
		return nil, err
	}
	if len(chain) != len(all) {
		return nil, fmt.Errorf("%d certificate(s) do not belong to the chain", len(all)-len(chain))
	}
	res := &BundleResult{Fullchain: out}
	last := chain[len(chain)-1]
	res.Complete = last.CheckSignatureFrom(last) == nil
	if res.Complete && !includeRoot && len(chain) > 1 {
		chain = chain[:len(chain)-1]
	}
	var pemOut []byte
	for _, c := range chain {
		res.Chain = append(res.Chain, c.Subject.String())
		pemOut = append(pemOut, certPEM(c)...)
	}
	if res.Changed, err = writeAll(outFile{out, pemOut, 0o644}); err != nil {
		return nil, err
	}
	return res, nil
}

// endCerts returns the certificates in all that signed none of the others.
func endCerts(all []*x509.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range all {
		if !slices.ContainsFunc(all, func(x *x509.Certificate) bool { return x != c && x.CheckSignatureFrom(c) == nil }) {
			out = append(out, c)
		}
	}
	return out
}

// orderChain returns leaf followed by each issuer found in all, up to a
// self-signed root or the last issuer present.
func orderChain(leaf *x509.Certificate, all []*x509.Certificate) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{leaf}
	for cur := leaf; cur.CheckSignatureFrom(cur) != nil; {
		i := slices.IndexFunc(all, func(x *x509.Certificate) bool { return x != cur && cur.CheckSignatureFrom(x) == nil })
		if i < 0 {
			break // issuer not supplied: the chain ends here
		}
		cur = all[i]
		if slices.Contains(chain, cur) {
			return nil, errors.New("certificates form a loop")
		}
		chain = append(chain, cur)
	}
	return chain, nil
}

// p12Encoder picks the PKCS#12 encryption profile.
func p12Encoder(legacy bool) *pkcs12.Encoder {
	if legacy {
		return pkcs12.LegacyDES
	}
	return pkcs12.Modern2023
}

// writeP12 writes key, leaf and ca as PKCS#12 to out (mode 0600). PKCS#12
// output is randomised, so an existing file that opens with pass and holds the
// same contents is kept.
func writeP12(out string, key crypto.Signer, leaf *x509.Certificate, ca []*x509.Certificate, pass []byte, legacy bool) (bool, error) {
	if old, err := os.ReadFile(out); err == nil { // #nosec G304 -- the operator names every output file
		if k, c, cas, err := pkcs12.DecodeChain(old, string(pass)); err == nil && c.Equal(leaf) &&
			isSignerFor(k, key) && slices.EqualFunc(cas, ca, certEqual) {
			return false, nil
		}
	}
	data, err := p12Encoder(legacy).Encode(key, leaf, ca, string(pass))
	if err != nil {
		return false, err
	}
	return writeAll(outFile{out, data, 0o600})
}

func certEqual(a, b *x509.Certificate) bool { return a.Equal(b) }

func parseAnyCSR(b []byte) (*x509.CertificateRequest, error) {
	der, err := certfmt.DecodeCSR(b)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// pubFingerprint is the SHA-256 of a public key's PKIX DER, "sha256:<hex>".
func pubFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// isSignerFor reports whether k is a signing key with the same public key as key.
func isSignerFor(k any, key crypto.Signer) bool {
	s, ok := k.(crypto.Signer)
	return ok && pubEqual(s.Public(), key.Public())
}
