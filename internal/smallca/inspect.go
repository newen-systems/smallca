package smallca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/newen-systems/smallca/internal/certfmt"
)

// CertView is the inspect output for one certificate.
type CertView struct {
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer"`
	Serial         string   `json:"serial"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	DaysLeft       int      `json:"days_left"`
	Expired        bool     `json:"expired"`
	SelfSigned     bool     `json:"self_signed"`
	Key            string   `json:"key"`
	Signature      string   `json:"signature_algorithm"`
	IsCA           bool     `json:"is_ca"`
	PathLen        *int     `json:"path_len,omitempty"`
	KeyUsage       []string `json:"key_usage,omitempty"`
	ExtKeyUsage    []string `json:"ext_key_usage,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	Emails         []string `json:"emails,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	PermittedDNS   []string `json:"permitted_dns,omitempty"`
	ExcludedDNS    []string `json:"excluded_dns,omitempty"`
	SubjectKeyID   string   `json:"subject_key_id,omitempty"`
	AuthorityKeyID string   `json:"authority_key_id,omitempty"`
	Fingerprint    string   `json:"fingerprint_sha256"`
}

// CSRView is the inspect output for a certificate signing request.
type CSRView struct {
	Subject        string   `json:"subject"`
	Key            string   `json:"key"`
	Signature      string   `json:"signature_algorithm"`
	SignatureValid bool     `json:"signature_valid"`
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	Emails         []string `json:"emails,omitempty"`
	Extensions     []string `json:"requested_extensions,omitempty"`
	Fingerprint    string   `json:"fingerprint_sha256"`
}

// InspectResult is the JSON output of certificate inspect: either the
// certificates in the file, in order, or one CSR.
type InspectResult struct {
	Certificates []CertView `json:"certificates,omitempty"`
	CSR          *CSRView   `json:"csr,omitempty"`
}

// Inspect decodes data as certificates (PEM bundle, DER or PKCS#7) or, failing
// that, as a CSR (PEM or DER).
func Inspect(data []byte) (*InspectResult, error) {
	if ders, err := certfmt.DecodeCerts(data); err == nil {
		res := &InspectResult{}
		for i, d := range ders {
			c, err := x509.ParseCertificate(d)
			if err != nil {
				if len(ders) == 1 {
					break // maybe a bare DER CSR; try below
				}
				return nil, fmt.Errorf("certificate %d: %w", i+1, err)
			}
			res.Certificates = append(res.Certificates, viewCert(c))
		}
		if len(res.Certificates) > 0 {
			return res, nil
		}
	}
	if strings.Contains(string(data), "PRIVATE KEY-----") {
		return nil, errors.New("input is a private key; smallca does not print keys")
	}
	der, err := certfmt.DecodeCSR(data)
	if err != nil {
		return nil, errors.New("input is neither a certificate nor a CSR (PEM, DER or PKCS#7)")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("input is neither a certificate nor a CSR (PEM, DER or PKCS#7)")
	}
	sum := sha256.Sum256(csr.Raw)
	v := &CSRView{
		Subject:        csr.Subject.String(),
		Key:            keyDesc(csr.PublicKey),
		Signature:      csr.SignatureAlgorithm.String(),
		SignatureValid: csr.CheckSignature() == nil,
		DNSNames:       csr.DNSNames,
		Emails:         csr.EmailAddresses,
		Fingerprint:    "sha256:" + hex.EncodeToString(sum[:]),
	}
	for _, ip := range csr.IPAddresses {
		v.IPAddresses = append(v.IPAddresses, ip.String())
	}
	for _, e := range csr.Extensions {
		name := e.Id.String()
		if n, ok := extNames[name]; ok {
			name = n
		}
		if e.Critical {
			name += " (critical)"
		}
		v.Extensions = append(v.Extensions, name)
	}
	return &InspectResult{CSR: v}, nil
}

func viewCert(c *x509.Certificate) CertView {
	left := c.NotAfter.Sub(now())
	v := CertView{
		Subject:        c.Subject.String(),
		Issuer:         c.Issuer.String(),
		Serial:         colonHex(c.SerialNumber.Bytes()),
		NotBefore:      c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:       c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:       int(left.Hours() / 24),
		Expired:        left <= 0,
		SelfSigned:     c.CheckSignatureFrom(c) == nil,
		Key:            keyDesc(c.PublicKey),
		Signature:      c.SignatureAlgorithm.String(),
		IsCA:           c.IsCA,
		ExtKeyUsage:    ekuNames(c),
		DNSNames:       c.DNSNames,
		Emails:         c.EmailAddresses,
		PermittedDNS:   c.PermittedDNSDomains,
		ExcludedDNS:    c.ExcludedDNSDomains,
		SubjectKeyID:   colonHex(c.SubjectKeyId),
		AuthorityKeyID: colonHex(c.AuthorityKeyId),
		Fingerprint:    Fingerprint(c),
	}
	if c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		n := c.MaxPathLen
		v.PathLen = &n
	}
	for bit, name := range keyUsageNames {
		if c.KeyUsage&(1<<bit) != 0 {
			v.KeyUsage = append(v.KeyUsage, name)
		}
	}
	for _, ip := range c.IPAddresses {
		v.IPAddresses = append(v.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		v.URIs = append(v.URIs, u.String())
	}
	return v
}

func keyDesc(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "EC " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := hex.EncodeToString(b)
	var out strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

// keyUsageNames is indexed by the bit position of x509.KeyUsage.
var keyUsageNames = []string{"digitalSignature", "contentCommitment", "keyEncipherment",
	"dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}

var ekuByValue = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth",
	x509.ExtKeyUsageClientAuth: "clientAuth", x509.ExtKeyUsageCodeSigning: "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection", x509.ExtKeyUsageTimeStamping: "timeStamping",
	x509.ExtKeyUsageOCSPSigning: "OCSPSigning",
}

func ekuNames(c *x509.Certificate) []string {
	var out []string
	for _, u := range c.ExtKeyUsage {
		if n, ok := ekuByValue[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", u))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

var extNames = map[string]string{
	"2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAltName",
	"2.5.29.19": "basicConstraints", "2.5.29.30": "nameConstraints", "2.5.29.37": "extKeyUsage",
}

// FetchChain connects to a TLS server and returns the chain it presents, in the
// order it sends it. target is host, host:port or https://host[:port]; the
// port defaults to 443. The chain is not verified: inspect shows what the
// server sends, trusted or not. Use certificate verify to judge trust.
func FetchChain(ctx context.Context, target, serverName string) ([]*x509.Certificate, string, error) {
	host, serverName := dialTarget(target, serverName)
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		// #nosec G402 -- inspect displays the chain without trusting it.
		Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, host, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, host, errors.New("server sent no certificates")
	}
	return certs, host, nil
}

// dialTarget turns host, host:port or https://host[:port] into host:port
// (port 443 by default) and the SNI name (default: the host).
func dialTarget(target, serverName string) (string, string) {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(host)
	}
	return host, serverName
}

// readInput reads a file, or stdin for "-".
func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(stdin, 16<<20))
	}
	return os.ReadFile(path) // #nosec G304 -- the operator names every input file
}

// writeInspectText prints res as aligned "Label: value" lines.
func writeInspectText(w io.Writer, res *InspectResult) {
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(w, "  %-16s %s\n", label+":", value)
		}
	}
	list := func(v []string) string { return strings.Join(v, ", ") }
	if res.CSR != nil {
		r := res.CSR
		fmt.Fprintln(w, "Certificate request")
		line("Subject", r.Subject)
		line("Key", r.Key)
		line("Signature", fmt.Sprintf("%s (%s)", r.Signature, map[bool]string{true: "valid", false: "INVALID"}[r.SignatureValid]))
		line("DNS names", list(r.DNSNames))
		line("IP addresses", list(r.IPAddresses))
		line("Emails", list(r.Emails))
		line("Extensions", list(r.Extensions))
		line("SHA-256", r.Fingerprint)
		return
	}
	for i, c := range res.Certificates {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "Certificate %d of %d\n", i+1, len(res.Certificates))
		line("Subject", c.Subject)
		issuer := c.Issuer
		if c.SelfSigned {
			issuer += " (self-signed)"
		}
		line("Issuer", issuer)
		line("Serial", c.Serial)
		state := fmt.Sprintf("%d days left", c.DaysLeft)
		if c.Expired {
			state = "EXPIRED"
		}
		line("Valid", fmt.Sprintf("%s to %s (%s)", c.NotBefore, c.NotAfter, state))
		line("Key", c.Key)
		line("Signature", c.Signature)
		ca := "no"
		if c.IsCA {
			ca = "yes, path length unlimited"
			if c.PathLen != nil {
				ca = fmt.Sprintf("yes, path length %d", *c.PathLen)
			}
		}
		line("CA", ca)
		line("Key usage", list(c.KeyUsage))
		line("Ext key usage", list(c.ExtKeyUsage))
		line("DNS names", list(c.DNSNames))
		line("IP addresses", list(c.IPAddresses))
		line("Emails", list(c.Emails))
		line("URIs", list(c.URIs))
		line("Permitted DNS", list(c.PermittedDNS))
		line("Excluded DNS", list(c.ExcludedDNS))
		line("Subject key ID", c.SubjectKeyID)
		line("Authority key ID", c.AuthorityKeyID)
		line("SHA-256", c.Fingerprint)
	}
}
