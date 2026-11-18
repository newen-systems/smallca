// Copyright 2026 the smallca authors
// SPDX-License-Identifier: Apache-2.0

package smallca

import (
	"cmp"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ConvertOptions names the inputs and every output of Convert. Empty output
// paths are not written.
type ConvertOptions struct {
	In            []string
	Pass          []byte // PKCS#12 or encrypted key password, for input and output
	Format        string // pem, der or p7b; empty picks one from each file extension
	Out           string // every certificate, in input order
	CertOut       string // the end certificate
	ChainOut      string // its issuers
	FullchainOut  string // the end certificate and its issuers
	KeyOut        string // the private key, unencrypted PKCS#8
	SplitDir      string // one file per certificate
	P12Out        string
	TruststoreOut string
	Legacy        bool
}

type ConvertResult struct {
	Changed      bool     `json:"changed"`
	Certificates []string `json:"certificates"`
	Key          bool     `json:"has_key"`
}

var formats = []string{"pem", "der", "p7b"}

// Convert reads certificates and at most one private key from PEM, DER,
// PKCS#7 and PKCS#12 files and writes them out in the requested forms.
func Convert(o ConvertOptions) (*ConvertResult, error) {
	if o.Format != "" && !slices.Contains(formats, o.Format) {
		return nil, fmt.Errorf("format %q, want pem, der or p7b", o.Format)
	}
	certs, key, err := readConvertInputs(o.In, o.Pass)
	if err != nil {
		return nil, err
	}
	if err := o.checkInputs(key); err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	if o.CertOut != "" || o.ChainOut != "" || o.FullchainOut != "" || o.P12Out != "" {
		leaf, err := findLeaf(certs, key)
		if err != nil {
			return nil, err
		}
		if chain, err = orderChain(leaf, certs); err != nil {
			return nil, err
		}
	}
	files, err := o.plainFiles(certs, chain, key)
	if err != nil {
		return nil, err
	}
	res := &ConvertResult{Key: key != nil}
	for _, c := range certs {
		res.Certificates = append(res.Certificates, c.Subject.String())
	}
	if res.Changed, err = writeAll(files...); err != nil {
		return nil, err
	}
	var c bool
	if o.P12Out != "" {
		if c, err = writeP12(o.P12Out, key, chain[0], chain[1:], o.Pass, o.Legacy); err != nil {
			return nil, err
		}
		res.Changed = res.Changed || c
	}
	if o.TruststoreOut != "" {
		if c, err = writeTrustStore(o.TruststoreOut, certs, o.Pass, o.Legacy); err != nil {
			return nil, err
		}
		res.Changed = res.Changed || c
	}
	return res, nil
}

// readConvertInputs collects the certificates, without duplicates, and the
// one private key from every input file.
func readConvertInputs(paths []string, pass []byte) ([]*x509.Certificate, crypto.Signer, error) {
	var certs []*x509.Certificate
	var key crypto.Signer
	for _, f := range paths {
		b, err := os.ReadFile(f) // #nosec G304 -- the operator names every input file
		if err != nil {
			return nil, nil, err
		}
		cs, k, err := decodeAny(f, b, pass)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range cs {
			if !slices.ContainsFunc(certs, c.Equal) {
				certs = append(certs, c)
			}
		}
		if k != nil && key != nil && !pubEqual(key.Public(), k.Public()) {
			return nil, nil, errors.New("the input holds more than one private key")
		}
		if k != nil {
			key = k
		}
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("the input holds no certificates")
	}
	return certs, key, nil
}

// checkInputs fails before anything is written when an output needs a key or
// a password the run does not have.
func (o ConvertOptions) checkInputs(key crypto.Signer) error {
	switch {
	case key == nil && o.KeyOut != "":
		return errors.New("--key-out: the input holds no private key")
	case key == nil && o.P12Out != "":
		return errors.New("--p12-out: the input holds no private key")
	case o.Pass == nil && (o.P12Out != "" || o.TruststoreOut != ""):
		return errors.New("--p12-out and --truststore-out need a password")
	}
	return nil
}

// plainFiles encodes every output except the PKCS#12 ones. chain is the end
// certificate and its issuers, empty when no output needs it.
func (o ConvertOptions) plainFiles(certs, chain []*x509.Certificate, key crypto.Signer) ([]outFile, error) {
	type certOut struct {
		path  string
		certs []*x509.Certificate
	}
	outs := []certOut{{o.Out, certs}, {o.CertOut, chain[:min(1, len(chain))]}, {o.FullchainOut, chain}}
	if o.ChainOut != "" {
		if len(chain) < 2 {
			return nil, errors.New("--chain-out: the input holds no issuer of the end certificate")
		}
		outs = append(outs, certOut{o.ChainOut, chain[1:]})
	}
	if o.SplitDir != "" {
		ext := cmp.Or(o.Format, "pem")
		for i, c := range certs {
			path := filepath.Join(o.SplitDir, fmt.Sprintf("%d-%s.%s", i+1, fileSlug(c), ext))
			outs = append(outs, certOut{path, []*x509.Certificate{c}})
		}
	}
	var files []outFile
	for _, w := range outs {
		if w.path == "" {
			continue
		}
		data, err := encodeCerts(o.formatFor(w.path), w.certs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", w.path, err)
		}
		files = append(files, outFile{w.path, data, 0o644})
	}
	if o.KeyOut != "" {
		data, err := o.encodeKey(o.KeyOut, key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.KeyOut, err)
		}
		files = append(files, outFile{o.KeyOut, data, 0o600})
	}
	return files, nil
}

// decodeAny reads certificates and any private key from PEM (certificates,
// PKCS#7 and keys in any order), DER, PKCS#7 or PKCS#12.
func decodeAny(name string, b, pass []byte) ([]*x509.Certificate, crypto.Signer, error) {
	if strings.Contains(string(b), "-----BEGIN") {
		return decodePEMFile(name, b, pass)
	}
	if certs, err := parseCerts(name, b); err == nil {
		return certs, nil, nil
	}
	p := string(pass)
	k, leaf, cas, err := pkcs12.DecodeChain(b, p)
	if err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("%s: key type %T cannot sign", name, k)
		}
		return append([]*x509.Certificate{leaf}, cas...), s, nil
	}
	if certs, err2 := pkcs12.DecodeTrustStore(b, p); err2 == nil {
		return certs, nil, nil
	}
	if pass == nil {
		return nil, nil, fmt.Errorf("%s: not PEM, DER or PKCS#7, and not a PKCS#12 file without a password", name)
	}
	return nil, nil, fmt.Errorf("%s: not PEM, DER or PKCS#7, and as PKCS#12: %w", name, err)
}

// decodePEMFile reads every PEM block: certificates, PKCS#7 and at most one
// private key.
func decodePEMFile(name string, b, pass []byte) ([]*x509.Certificate, crypto.Signer, error) {
	var certs []*x509.Certificate
	var key crypto.Signer
	for block, rest := pem.Decode(b); block != nil; block, rest = pem.Decode(rest) {
		one := pem.EncodeToMemory(block)
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			cs, err := parseCerts(name, one)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cs...)
			continue
		}
		if key != nil {
			return nil, nil, fmt.Errorf("%s: holds more than one private key", name)
		}
		k, err := decodePEMKey(name, one, pass)
		if err != nil {
			return nil, nil, err
		}
		key = k
	}
	if certs == nil && key == nil {
		return nil, nil, fmt.Errorf("%s: no PEM certificates or keys found", name)
	}
	return certs, key, nil
}

// decodePEMKey parses one PEM private key, using pass only when it is encrypted.
func decodePEMKey(name string, one, pass []byte) (crypto.Signer, error) {
	if !KeyEncrypted(one) {
		return parseKey(name, one, nil)
	}
	if pass == nil {
		return nil, fmt.Errorf("%s: the private key is encrypted: give its password", name)
	}
	return parseKey(name, one, pass)
}

// findLeaf is the certificate matching key, or without a key the one
// certificate that signed none of the others.
func findLeaf(certs []*x509.Certificate, key crypto.Signer) (*x509.Certificate, error) {
	if key != nil {
		i := slices.IndexFunc(certs, func(c *x509.Certificate) bool { return keyMatches(key, c) })
		if i < 0 {
			return nil, errors.New("the private key matches none of the certificates")
		}
		return certs[i], nil
	}
	ends := endCerts(certs)
	if len(ends) != 1 {
		return nil, fmt.Errorf("found %d end certificates, want exactly 1: give the private key, or use --out or --split-dir", len(ends))
	}
	return ends[0], nil
}

// formatFor is --format, or the format the file extension implies.
func (o ConvertOptions) formatFor(path string) string {
	if o.Format != "" {
		return o.Format
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".der", ".cer":
		return "der"
	case ".p7b", ".p7c":
		return "p7b"
	}
	return "pem"
}

func (o ConvertOptions) encodeKey(path string, key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	switch o.formatFor(path) {
	case "der":
		return der, nil
	case "p7b":
		return nil, errors.New("a private key cannot be written as PKCS#7")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeCerts(format string, certs []*x509.Certificate) ([]byte, error) {
	switch format {
	case "der":
		if len(certs) != 1 {
			return nil, fmt.Errorf("DER holds one certificate, not %d: use p7b, pem or --split-dir", len(certs))
		}
		return certs[0].Raw, nil
	case "p7b":
		return encodePKCS7(certs)
	}
	var out []byte
	for _, c := range certs {
		out = append(out, certPEM(c)...)
	}
	return out, nil
}

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// encodePKCS7 writes certs as a degenerate PKCS#7 SignedData (RFC 2315): no
// content and no signers, the .p7b form Windows and Java import.
func encodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	emptySet := asn1.RawValue{Tag: asn1.TagSet, IsCompound: true}
	sd, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{1, emptySet, struct{ ContentType asn1.ObjectIdentifier }{oidData},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw}, emptySet})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}

var slugUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// fileSlug names a certificate's file after its common name.
func fileSlug(c *x509.Certificate) string {
	s := strings.Trim(slugUnsafe.ReplaceAllString(c.Subject.CommonName, "_"), "._")
	if s == "" {
		return "certificate"
	}
	return s
}

// writeTrustStore writes certs as a Java PKCS#12 trust store, keeping an
// existing file that opens with pass and holds the same certificates.
func writeTrustStore(out string, certs []*x509.Certificate, pass []byte, legacy bool) (bool, error) {
	if old, err := os.ReadFile(out); err == nil { // #nosec G304 -- the operator names every output file
		if cs, err := pkcs12.DecodeTrustStore(old, string(pass)); err == nil && slices.EqualFunc(cs, certs, certEqual) {
			return false, nil
		}
	}
	data, err := p12Encoder(legacy).EncodeTrustStore(certs, string(pass))
	if err != nil {
		return false, err
	}
	return writeAll(outFile{out, data, 0o644})
}
