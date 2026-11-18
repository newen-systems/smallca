// Package csrutil parses subordinate-CA CSRs strictly.
// Decode/CheckSignature flow adapted from smallstep/step-issuer v0.12.0
// (Apache-2.0); see NOTICE.
package csrutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/newen-systems/smallca/internal/certfmt"
)

const minRSABits = 2048

// Critical extensions many CA installers legitimately put on a CSR
// (basicConstraints, keyUsage). Anything else marked critical is rejected;
// non-critical extensions are ignored entirely (never copied: the issued-cert
// template is built from scratch by the caller).
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// ParseCSR enforces: exactly one request, valid DER, valid PKCS#10 signature,
// allowed key algorithm/strength, no unknown critical extensions.
//
// The container may be PEM ("CERTIFICATE REQUEST" or the "NEW CERTIFICATE
// REQUEST" label Windows certreq writes) or bare DER, certfmt normalises those
// before any of the checks below. What is accepted at the boundary widened;
// what is enforced about the request itself did not.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	der, err := certfmt.DecodeCSR(pemBytes)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if err := checkKey(csr.PublicKey); err != nil {
		return nil, err
	}
	for _, ext := range csr.Extensions {
		if isUnknownCritical(ext) {
			return nil, fmt.Errorf("unknown critical CSR extension %s", ext.Id)
		}
	}
	return csr, nil
}

func checkKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return fmt.Errorf("RSA key %d bits, minimum %d", k.N.BitLen(), minRSABits)
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return fmt.Errorf("ECDSA curve %s not allowed", k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("public key type %T not allowed", pub)
	}
	return nil
}

// isUnknownCritical reports whether ext is marked critical and is not one of the
// tolerated OIDs (basicConstraints, keyUsage). Non-critical extensions are never
// unknown-critical, so they pass.
func isUnknownCritical(ext pkix.Extension) bool {
	if !ext.Critical {
		return false
	}
	return !ext.Id.Equal(oidBasicConstraints) && !ext.Id.Equal(oidKeyUsage)
}
