// Copyright 2026 the smallca authors
// SPDX-License-Identifier: Apache-2.0

package smallca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/newen-systems/smallca/internal/certfmt"
)

// convertFixture issues a leaf under the tools CA and returns its paths.
func convertFixture(t *testing.T) (w, crt, key, caCrt, rootCrt, pw string) {
	t.Helper()
	caCrt, caKey, rootCrt := issuer(t)
	w = t.TempDir()
	crt, key = filepath.Join(w, "c.crt"), filepath.Join(w, "c.key")
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "c.example.test",
		"--cert-out", crt, "--key-out", key)
	pw = filepath.Join(w, "pw")
	if err := os.WriteFile(pw, []byte("convert-pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, crt, key, caCrt, rootCrt, pw
}

func TestConvertP12RoundTrip(t *testing.T) {
	w, crt, key, caCrt, rootCrt, pw := convertFixture(t)
	pfx := filepath.Join(w, "c.pfx")
	// The input order does not matter: the key picks the end certificate.
	args := []string{"certificate", "convert", "--in", rootCrt, "--in", key, "--in", caCrt, "--in", crt,
		"--p12-out", pfx, "--password-file", pw}
	if m := mustRun(t, "", args...); m["changed"] != true || m["has_key"] != true {
		t.Fatalf("to p12 %v", m)
	}
	if m := mustRun(t, "", args...); m["changed"] != false {
		t.Fatal("p12 re-run changed")
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		openssl(t, "pkcs12", "-in", pfx, "-passin", "pass:convert-pass", "-noout")
	}

	out := func(n string) string { return filepath.Join(w, n) }
	args = []string{"certificate", "convert", "--in", pfx, "--password-file", pw, "--cert-out", out("o.crt"),
		"--key-out", out("o.key"), "--chain-out", out("chain.pem"), "--fullchain-out", out("full.pem")}
	mustRun(t, "", args...)
	if m := mustRun(t, "", args...); m["changed"] != false {
		t.Fatal("split re-run changed")
	}
	same := func(a, b string) {
		t.Helper()
		x, _ := os.ReadFile(a)
		y, _ := os.ReadFile(b)
		if !bytes.Equal(x, y) {
			t.Fatalf("%s differs from %s", a, b)
		}
	}
	same(out("o.crt"), crt)
	if st, _ := os.Stat(out("o.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}
	if m := mustRun(t, "", "certificate", "match", "--cert", out("o.crt"), "--key", out("o.key")); m["match"] != true {
		t.Fatalf("extracted key %v", m)
	}
	for f, n := range map[string]int{"chain.pem": 2, "full.pem": 3} {
		if got := bytes.Count(must(os.ReadFile(out(f))), []byte("BEGIN CERTIFICATE")); got != n {
			t.Fatalf("%s holds %d certificates, want %d", f, got, n)
		}
	}
	// A wrong or missing password is an error, not an empty result.
	for _, extra := range [][]string{{}, {"--password-stdin"}} {
		a := append([]string{"certificate", "convert", "--in", pfx, "--out", out("x.pem")}, extra...)
		if rc, _, stderr := run(t, "wrong\n", a...); rc != ExitError || !strings.Contains(stderr, "PKCS#12") {
			t.Fatalf("bad password rc=%d %s", rc, stderr)
		}
	}
}

func TestConvertFormats(t *testing.T) {
	w, crt, _, caCrt, rootCrt, _ := convertFixture(t)
	full := filepath.Join(w, "in.pem")
	if err := os.WriteFile(full, append(append(must(os.ReadFile(crt)), must(os.ReadFile(caCrt))...), must(os.ReadFile(rootCrt))...), 0o600); err != nil {
		t.Fatal(err)
	}
	p7b := filepath.Join(w, "all.p7b")
	mustRun(t, "", "certificate", "convert", "--in", full, "--out", p7b)
	ders, err := certfmt.DecodeCerts(must(os.ReadFile(p7b)))
	if err != nil || len(ders) != 3 {
		t.Fatalf("p7b decode %d %v", len(ders), err)
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		if s := openssl(t, "pkcs7", "-inform", "der", "-in", p7b, "-print_certs", "-noout"); strings.Count(s, "subject=") != 3 {
			t.Fatalf("openssl p7b %s", s)
		}
	}
	back := filepath.Join(w, "back.pem")
	mustRun(t, "", "certificate", "convert", "--in", p7b, "--out", back)
	if !bytes.Equal(must(os.ReadFile(back)), must(os.ReadFile(full))) {
		t.Fatal("p7b round trip changed the certificates")
	}

	split := filepath.Join(w, "split")
	m := mustRun(t, "", "certificate", "convert", "--in", p7b, "--split-dir", split, "--format", "der")
	if len(m["certificates"].([]any)) != 3 || m["certificates"].([]any)[0] != "CN=c.example.test" {
		t.Fatalf("split %v", m)
	}
	names, _ := filepath.Glob(filepath.Join(split, "*"))
	if len(names) != 3 || filepath.Base(names[0]) != "1-c.example.test.der" {
		t.Fatalf("split files %v", names)
	}
	if _, err := x509.ParseCertificate(must(os.ReadFile(names[0]))); err != nil {
		t.Fatal(err)
	}
	// .cer means DER without --format.
	cer := filepath.Join(w, "leaf.cer")
	mustRun(t, "", "certificate", "convert", "--in", crt, "--cert-out", cer)
	if _, err := x509.ParseCertificate(must(os.ReadFile(cer))); err != nil {
		t.Fatalf(".cer is not DER: %v", err)
	}

	ts := filepath.Join(w, "ts.p12")
	pw := filepath.Join(w, "pw")
	tsArgs := []string{"certificate", "convert", "--in", caCrt, "--in", rootCrt, "--truststore-out", ts, "--password-file", pw}
	mustRun(t, "", tsArgs...)
	if m := mustRun(t, "", tsArgs...); m["changed"] != false {
		t.Fatal("truststore re-run changed")
	}
	if certs, err := pkcs12.DecodeTrustStore(must(os.ReadFile(ts)), "convert-pass"); err != nil || len(certs) != 2 {
		t.Fatalf("truststore %d %v", len(certs), err)
	}
}

func TestConvertErrors(t *testing.T) {
	w, crt, key, caCrt, _, _ := convertFixture(t)
	other, otherKey, _ := issuer(t)
	o := filepath.Join(w, "o")
	for name, c := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no output":         {[]string{"--in", crt}, ExitUsage, "at least one output"},
		"no input":          {[]string{"--out", o}, ExitUsage, "--in"},
		"bad format":        {[]string{"--in", crt, "--out", o, "--format", "jks"}, ExitError, "want pem, der or p7b"},
		"der of two":        {[]string{"--in", crt, "--in", caCrt, "--out", o + ".der"}, ExitError, "DER holds one"},
		"key as p7b":        {[]string{"--in", key, "--in", crt, "--key-out", o + ".p7b"}, ExitError, "PKCS#7"},
		"no key":            {[]string{"--in", crt, "--key-out", o}, ExitError, "no private key"},
		"no issuer":         {[]string{"--in", crt, "--chain-out", o}, ExitError, "no issuer"},
		"p12 no password":   {[]string{"--in", crt, "--in", key, "--p12-out", o}, ExitError, "need a password"},
		"two keys":          {[]string{"--in", key, "--in", otherKey, "--out", o}, ExitError, "more than one private key"},
		"key matches none":  {[]string{"--in", otherKey, "--in", crt, "--cert-out", o}, ExitError, "matches none"},
		"two end certs":     {[]string{"--in", crt, "--in", other, "--cert-out", o}, ExitError, "end certificates"},
		"key only":          {[]string{"--in", key, "--key-out", o}, ExitError, "no certificates"},
		"not a certificate": {[]string{"--in", filepath.Join(w, "pw"), "--out", o}, ExitError, "PKCS#12"},
	} {
		rc, _, stderr := run(t, "", append([]string{"certificate", "convert"}, c.args...)...)
		if rc != c.code || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: rc=%d want %d, stderr %s", name, rc, c.code, stderr)
		}
	}
}

func TestConvertEncryptedKeyAndSlug(t *testing.T) {
	needOpenSSL(t)
	w, crt, key, _, _, pw := convertFixture(t)
	enc := filepath.Join(w, "enc.key")
	openssl(t, "pkey", "-in", key, "-aes256", "-passout", "pass:convert-pass", "-out", enc)
	if rc, _, stderr := run(t, "", "certificate", "convert", "--in", enc, "--in", crt, "--key-out", filepath.Join(w, "x")); rc != ExitError || !strings.Contains(stderr, "encrypted") {
		t.Fatalf("encrypted key without password rc=%d %s", rc, stderr)
	}
	plain := filepath.Join(w, "clear.key")
	mustRun(t, "", "certificate", "convert", "--in", enc, "--in", crt, "--key-out", plain, "--password-file", pw)
	if m := mustRun(t, "", "certificate", "match", "--cert", crt, "--key", plain); m["match"] != true {
		t.Fatal("decrypted key does not match")
	}
	for cn, want := range map[string]string{"a b/c": "a_b_c", "...": "certificate", "": "certificate"} {
		if got := fileSlug(&x509.Certificate{Subject: pkix.Name{CommonName: cn}}); got != want {
			t.Errorf("fileSlug(%q) = %q, want %q", cn, got, want)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
