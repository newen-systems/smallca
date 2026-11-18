package csrutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
)

func makeCSR(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Certificate Authority", Organization: []string{"EXAMPLE.TEST"}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseValidRSA2048(t *testing.T) {
	csr, err := ParseCSR(makeCSR(t, rsaKey(t, 2048)))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "Certificate Authority" {
		t.Fatalf("subject: %v", csr.Subject)
	}
}

func TestParseValidECDSAP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ParseCSR(makeCSR(t, k)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectWeakRSA(t *testing.T) {
	if _, err := ParseCSR(makeCSR(t, rsaKey(t, 1024))); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
}

func TestRejectTrailingData(t *testing.T) {
	b := append(makeCSR(t, rsaKey(t, 2048)), []byte("trailing")...)
	if _, err := ParseCSR(b); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestRejectTwoBlocks(t *testing.T) {
	one := makeCSR(t, rsaKey(t, 2048))
	if _, err := ParseCSR(append(one, one...)); err == nil {
		t.Fatal("two PEM blocks accepted")
	}
}

func TestRejectWrongPEMType(t *testing.T) {
	der, _ := pem.Decode(makeCSR(t, rsaKey(t, 2048)))
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der.Bytes})
	if _, err := ParseCSR(b); err == nil {
		t.Fatal("wrong PEM type accepted")
	}
}

func TestRejectBadSignature(t *testing.T) {
	raw := makeCSR(t, rsaKey(t, 2048))
	blk, _ := pem.Decode(raw)
	blk.Bytes[len(blk.Bytes)-1] ^= 0xff // corrupt signature bytes
	if _, err := ParseCSR(pem.EncodeToMemory(blk)); err == nil {
		t.Fatal("corrupted signature accepted")
	}
}

// makeCSRWithExtension builds a signed CSR carrying one extra extension with the
// given OID and criticality, so the unknown-critical policy can be exercised end
// to end (CreateCertificateRequest marshals ExtraExtensions, and their Critical
// flag, into the CSR's extensionRequest attribute).
func makeCSRWithExtension(t *testing.T, oid asn1.ObjectIdentifier, critical bool) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Certificate Authority"},
		ExtraExtensions: []pkix.Extension{{
			Id:       oid,
			Critical: critical,
			Value:    []byte{0x05, 0x00}, // ASN.1 NULL, arbitrary opaque value
		}},
	}, rsaKey(t, 2048))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestRejectUnknownCriticalExtension(t *testing.T) {
	b := makeCSRWithExtension(t, asn1.ObjectIdentifier{1, 2, 3, 4, 4242}, true)
	// Guard the precondition: ParseCSR rejecting the CSR is only meaningful if the
	// unknown extension is still marked critical after the CreateCertificateRequest
	// -> ParseCertificateRequest round trip. Re-parse here and assert the critical
	// flag survived before trusting the rejection below.
	blk, _ := pem.Decode(b)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var sawCritical bool
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 4242}) && ext.Critical {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Fatal("precondition failed: critical unknown extension did not survive CSR round trip")
	}
	if _, err := ParseCSR(b); err == nil {
		t.Fatal("unknown critical extension accepted")
	}
}

func TestAcceptUnknownNonCriticalExtension(t *testing.T) {
	b := makeCSRWithExtension(t, asn1.ObjectIdentifier{1, 2, 3, 4, 4242}, false)
	if _, err := ParseCSR(b); err != nil {
		t.Fatalf("unknown non-critical extension rejected: %v", err)
	}
}

// Windows `certreq` labels its PKCS#10 output "NEW CERTIFICATE REQUEST". The DER
// is identical to openssl's, so an AD CS request must parse to the same CSR and
// still be subject to every check below the container, a widened container is
// not a widened policy. The AD CS label is accepted so Windows CSRs parse.
func TestParseADCSNewCertificateRequestLabel(t *testing.T) {
	key := rsaKey(t, 2048)
	pemBytes := makeCSR(t, key)

	block, _ := pem.Decode(pemBytes)
	adcs := pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: block.Bytes})

	std, err := ParseCSR(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCSR(adcs)
	if err != nil {
		t.Fatalf("AD CS-labelled request rejected: %v", err)
	}
	if string(got.Raw) != string(std.Raw) {
		t.Fatal("AD CS label produced a different request")
	}
}

// A request with no armour at all, what `openssl req -outform DER` and some
// Windows exports produce.
func TestParseBareDER(t *testing.T) {
	pemBytes := makeCSR(t, rsaKey(t, 2048))
	block, _ := pem.Decode(pemBytes)

	got, err := ParseCSR(block.Bytes)
	if err != nil {
		t.Fatalf("bare DER rejected: %v", err)
	}
	if got.Subject.CommonName != "Certificate Authority" {
		t.Fatalf("subject: %v", got.Subject)
	}
}

// Widening the container must not weaken key policy: a 1024-bit request is still
// refused when it arrives as bare DER or under the AD CS label.
func TestWeakKeyRejectedInEveryContainer(t *testing.T) {
	pemBytes := makeCSR(t, rsaKey(t, 1024))
	block, _ := pem.Decode(pemBytes)
	adcs := pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: block.Bytes})

	for name, in := range map[string][]byte{
		"PEM":      pemBytes,
		"bare DER": block.Bytes,
		"AD CS":    adcs,
	} {
		if _, err := ParseCSR(in); err == nil {
			t.Fatalf("%s: weak RSA key accepted", name)
		}
	}
}
