// Package certfmt decodes the container formats an external CA is likely to hand
// an operator, normalising each to DER for the strict parsers downstream.
//
// Scope is narrow: it ingests many formats into the one form smallca works in.
// It is not a converter: there is no format-to-format matrix here, and nothing
// in this package touches, decrypts or writes private key material.
// Certificates and CSRs are public data; PKCS#12 stays with `openssl pkcs12`.
package certfmt

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

// PEM block types accepted for a certification request. Windows `certreq` writes
// "NEW CERTIFICATE REQUEST"; openssl and most CA toolchains write the RFC 7468 name.
// The DER inside is identical, only the label differs.
var csrPEMTypes = map[string]bool{
	"CERTIFICATE REQUEST":     true,
	"NEW CERTIFICATE REQUEST": true,
}

// pkcs7PEMTypes are the labels seen on ASCII-armoured PKCS#7. openssl writes
// "PKCS7" (verified against the testdata fixture); "PKCS #7" appears in output
// from some other toolchains. No label is accepted here that a real producer has
// not been observed to emit.
var pkcs7PEMTypes = map[string]bool{
	"PKCS7":   true,
	"PKCS #7": true,
}

// oidSignedData identifies a PKCS#7 SignedData ContentInfo (RFC 2315 §9.1).
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// DecodeCSR normalises a certification request to DER. It accepts a PEM block
// labelled either "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST", or bare
// DER with no armour at all.
//
// Exactly one request is allowed: trailing data after the PEM block is an error.
// Ambiguity about WHICH request is being signed is a security property, not a
// usability wart.
func DecodeCSR(data []byte) ([]byte, error) {
	if !looksPEM(data) {
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, errors.New("empty input")
		}
		return data, nil // bare DER; the caller's strict parser validates it
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("unexpected data after first PEM block")
	}
	if !csrPEMTypes[block.Type] {
		return nil, fmt.Errorf("PEM type %q, want CERTIFICATE REQUEST or NEW CERTIFICATE REQUEST", block.Type)
	}
	if len(block.Bytes) == 0 {
		return nil, errors.New("empty PEM block")
	}
	return block.Bytes, nil
}

// DecodeCerts normalises one or more certificates to DER, in file order. It
// accepts a PEM bundle of CERTIFICATE blocks, bare DER holding a single
// certificate, or a PKCS#7 (.p7b) chain, armoured or binary, as emitted by
// AD CS and `openssl crl2pkcs7`.
func DecodeCerts(data []byte) ([][]byte, error) {
	if !looksPEM(data) {
		return decodeBinaryCerts(data)
	}
	return decodePEMCerts(data)
}

// decodeBinaryCerts handles un-armoured input: a PKCS#7 ContentInfo if it parses
// as one, otherwise a single bare certificate DER.
func decodeBinaryCerts(data []byte) ([][]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty input")
	}
	if ders, ok := pkcs7Certificates(data); ok {
		if len(ders) == 0 {
			return nil, errors.New("PKCS#7 blob carries no certificates")
		}
		return ders, nil
	}
	return [][]byte{data}, nil
}

// decodePEMCerts walks every PEM block, accepting CERTIFICATE blocks directly and
// unwrapping any PKCS#7 block it meets. A block of any other type is an error
// rather than a silent skip, a file that is not what the operator thinks it is
// should say so.
func decodePEMCerts(data []byte) ([][]byte, error) {
	var out [][]byte
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("trailing data is not a PEM block")
		}
		if len(block.Bytes) == 0 {
			return nil, fmt.Errorf("empty PEM block %q", block.Type)
		}
		switch {
		case block.Type == "CERTIFICATE":
			out = append(out, block.Bytes)
		case pkcs7PEMTypes[block.Type]:
			ders, ok := pkcs7Certificates(block.Bytes)
			if !ok {
				return nil, fmt.Errorf("PEM block %q is not a parseable PKCS#7 blob", block.Type)
			}
			out = append(out, ders...)
		default:
			return nil, fmt.Errorf("PEM block %q is not a certificate", block.Type)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	return out, nil
}

// contentInfo is the PKCS#7 outer wrapper (RFC 2315 §7).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is RFC 2315 §9.1. Only Certificates is read; every other field is
// kept raw because a ".p7b" chain is a DEGENERATE SignedData, no content and no
// signers, and validating fields nobody uses would reject legitimate files.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// pkcs7Certificates extracts the certificates from a PKCS#7 SignedData. The bool
// is true when the input parses as PKCS#7 SignedData, so callers can fall back
// to treating it as a bare certificate rather than surfacing an ASN.1 error.
func pkcs7Certificates(der []byte) ([][]byte, bool) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, false
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, false
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, false
	}
	return splitDER(sd.Certificates.Bytes), true
}

// splitDER walks a concatenation of DER elements (the SET OF inside a PKCS#7
// certificates field) and returns each element's full encoding.
func splitDER(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return out
		}
		out = append(out, v.FullBytes)
		b = rest
	}
	return out
}

// looksPEM reports whether the input is ASCII-armoured. PEM is 7-bit text with a
// "-----BEGIN" preamble; DER starts with an ASN.1 SEQUENCE tag (0x30), which
// cannot begin a PEM file.
func looksPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}
