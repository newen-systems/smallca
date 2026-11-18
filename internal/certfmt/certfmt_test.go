package certfmt

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// Fixtures in testdata/ are emitted by openssl, not by this package, so these
// tests prove interop with what real tools produce rather than round-tripping
// our own encoder. csr_adcs.req carries the "NEW CERTIFICATE REQUEST" label
// Windows certreq writes; the DER inside is byte-identical to csr_openssl.pem.
// Fixture filenames, named once so the tests read as intent rather than paths.
const (
	fxCSRPEM     = "csr_openssl.pem"
	fxCSRADCS    = "csr_adcs.req"
	fxCSRDER     = "csr_bare.der"
	fxCertPEM    = "cert_single.pem"
	fxCertDER    = "cert_bare.der"
	fxChainPEM   = "chain_bundle.pem"
	fxChainP7B   = "chain.p7b"
	fxChainP7PEM = "chain_p7.pem"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeCSRAcceptedForms(t *testing.T) {
	want := mustParseCSR(t, read(t, fxCSRDER))

	for _, name := range []string{fxCSRPEM, fxCSRADCS, fxCSRDER} {
		t.Run(name, func(t *testing.T) {
			der, err := DecodeCSR(read(t, name))
			if err != nil {
				t.Fatalf("DecodeCSR: %v", err)
			}
			got := mustParseCSR(t, der)
			// Every accepted container must yield the SAME request, the label
			// and armour are packaging, not content.
			if got.Subject.String() != want.Subject.String() {
				t.Fatalf("subject %q, want %q", got.Subject, want.Subject)
			}
			if string(got.Raw) != string(want.Raw) {
				t.Fatal("DER differs between container formats")
			}
		})
	}
}

func TestDecodeCSRRejected(t *testing.T) {
	valid := read(t, fxCSRPEM)

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"whitespace only", []byte("   \n\t ")},
		{"wrong PEM type", read(t, fxCertPEM)},
		{"trailing data after block", append(append([]byte{}, valid...), []byte("trailing junk")...)},
		{"two requests", append(append([]byte{}, valid...), valid...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeCSR(tc.in); err == nil {
				t.Fatal("accepted input that should be rejected")
			}
		})
	}
}

func TestDecodeCertsAcceptedForms(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		count int
	}{
		{"single PEM", fxCertPEM, 1},
		{"bare DER", fxCertDER, 1},
		{"PEM bundle", fxChainPEM, 2},
		{"binary PKCS#7", fxChainP7B, 2},
		{"armoured PKCS#7", fxChainP7PEM, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ders, err := DecodeCerts(read(t, tc.file))
			if err != nil {
				t.Fatalf("DecodeCerts: %v", err)
			}
			if len(ders) != tc.count {
				t.Fatalf("got %d certificates, want %d", len(ders), tc.count)
			}
			// Each returned blob must be a parseable certificate, not just bytes
			// that happened to survive the walk.
			for i, der := range ders {
				if _, err := x509.ParseCertificate(der); err != nil {
					t.Fatalf("certificate %d does not parse: %v", i, err)
				}
			}
		})
	}
}

// The PEM bundle and the PKCS#7 chain were built from the same two certificates
// in the same order, so both containers must yield the same DER sequence.
func TestDecodeCertsContainersAgree(t *testing.T) {
	bundle, err := DecodeCerts(read(t, fxChainPEM))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := DecodeCerts(read(t, fxChainP7B))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) != len(p7) {
		t.Fatalf("bundle has %d certs, p7b has %d", len(bundle), len(p7))
	}
	for i := range bundle {
		if string(bundle[i]) != string(p7[i]) {
			t.Fatalf("certificate %d differs between PEM bundle and PKCS#7", i)
		}
	}
}

func TestDecodeCertsRejected(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"whitespace only", []byte("  \n ")},
		{"a CSR is not a certificate", read(t, fxCSRPEM)},
		{"garbage after a valid block", append(append([]byte{}, read(t, fxCertPEM)...), []byte("-----BEGIN nonsense")...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeCerts(tc.in); err == nil {
				t.Fatal("accepted input that should be rejected")
			}
		})
	}
}

func mustParseCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// pkcs7Certificates reports whether the input is PKCS#7, so callers can fall
// back to treating un-armoured bytes as a bare certificate. These pin that
// discrimination: only a SignedData ContentInfo counts.
func TestPKCS7Detection(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		isP7 bool
	}{
		{"real p7b", read(t, fxChainP7B), true},
		{"a bare certificate is not PKCS#7", read(t, fxCertDER), false},
		{"not ASN.1 at all", []byte{0x30, 0x03, 0xff, 0xff, 0xff}, false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := pkcs7Certificates(tc.in)
			if ok != tc.isP7 {
				t.Fatalf("detected PKCS#7 = %v, want %v", ok, tc.isP7)
			}
		})
	}
}

// An armoured PKCS7 block whose payload is not PKCS#7 must error rather than be
// silently skipped or mistaken for a certificate.
func TestArmouredPKCS7WithGarbagePayload(t *testing.T) {
	bad := []byte("-----BEGIN PKCS7-----\nMIIBAAAA\n-----END PKCS7-----\n")
	if _, err := DecodeCerts(bad); err == nil {
		t.Fatal("accepted a PKCS7 block with a non-PKCS#7 payload")
	}
}

// A PKCS#7 blob that parses but carries no certificates is an error: the caller
// asked for certificates and got a container that has none.
func TestEmptyPKCS7Rejected(t *testing.T) {
	// SignedData ContentInfo with an absent certificates field.
	empty := []byte{
		0x30, 0x13,
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
		0xa0, 0x06, 0x30, 0x04, 0x02, 0x01, 0x01, 0x31, 0x00,
	}
	if _, ok := pkcs7Certificates(empty); ok {
		if _, err := DecodeCerts(empty); err == nil {
			t.Fatal("accepted a PKCS#7 blob carrying no certificates")
		}
	}
}
