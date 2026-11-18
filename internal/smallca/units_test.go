package smallca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// selfSigned returns a throwaway CA certificate and key for unit tests.
func selfSigned(t *testing.T, notAfter time.Time, pathLen int) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unit"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: pathLen, MaxPathLenZero: pathLen == 0, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func TestChildNotAfter(t *testing.T) {
	parent, _ := selfSigned(t, time.Now().Add(24*time.Hour), 1)
	if na, err := childNotAfter(parent, 48*time.Hour); err != nil || !na.Equal(parent.NotAfter) {
		t.Fatalf("not capped: %v %v", na, err)
	}
	if na, err := childNotAfter(parent, time.Hour); err != nil || !na.Before(parent.NotAfter) {
		t.Fatalf("shorter validity changed: %v %v", na, err)
	}
	expired, _ := selfSigned(t, time.Now().Add(-time.Minute), 1)
	if _, err := childNotAfter(expired, time.Hour); err == nil {
		t.Fatal("expired issuer accepted")
	}
}

func TestCheckPathLenAndProfile(t *testing.T) {
	unlimited, _ := selfSigned(t, time.Now().Add(time.Hour), -1)
	unlimited.MaxPathLen, unlimited.MaxPathLenZero = -1, false
	if err := checkPathLen(unlimited, 5); err != nil {
		t.Fatalf("unconstrained parent refused: %v", err)
	}
	two, _ := selfSigned(t, time.Now().Add(time.Hour), 2)
	for pl, ok := range map[int]bool{0: true, 1: true, 2: false, -1: false} {
		if err := checkPathLen(two, pl); (err == nil) != ok {
			t.Errorf("checkPathLen(2, %d) err=%v", pl, err)
		}
	}
	zero, _ := selfSigned(t, time.Now().Add(time.Hour), 0)
	if !sameCAProfile(zero, 0, nil) || sameCAProfile(zero, 1, nil) || sameCAProfile(zero, 0, []string{"x"}) {
		t.Fatal("sameCAProfile with path length 0")
	}
	if !sameCAProfile(unlimited, -1, nil) {
		t.Fatal("sameCAProfile unconstrained")
	}
}

func TestKeySpecResolve(t *testing.T) {
	good := map[KeySpec]KeySpec{
		{}:                        {Kty: "EC", Crv: "P-384"},
		{Kty: "ec", Crv: "P-256"}: {Kty: "EC", Crv: "P-256"},
		{Kty: "RSA"}:              {Kty: "RSA", Size: 3072},
		{Kty: "rsa", Size: 2048}:  {Kty: "RSA", Size: 2048},
	}
	for in, want := range good {
		if got, err := in.Resolve("P-384"); err != nil || got != want {
			t.Errorf("Resolve(%+v) = %+v, %v", in, got, err)
		}
	}
	for _, bad := range []KeySpec{{Kty: "OKP"}, {Kty: "EC", Size: 2048}, {Kty: "RSA", Crv: "P-256"}, {Kty: "RSA", Size: 1024}, {Crv: "P-521"}} {
		if _, err := bad.Resolve("P-384"); err == nil {
			t.Errorf("Resolve(%+v) accepted", bad)
		}
	}
	if _, err := (KeySpec{Kty: "EC"}).Generate(); err == nil {
		t.Fatal("unresolved spec generated a key")
	}
}

func TestKeyDescAndPurpose(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		pub  any
		want string
	}{{&ec.PublicKey, "EC P-384"}, {&r.PublicKey, "RSA 2048"}, {ed, "Ed25519"}, {"x", "string"}} {
		if got := keyDesc(c.pub); got != c.want {
			t.Errorf("keyDesc = %q, want %q", got, c.want)
		}
	}
	for p, n := range map[string]int{"server": 1, "client": 1, "both": 2} {
		if eku, err := PurposeEKU(p); err != nil || len(eku) != n {
			t.Errorf("PurposeEKU(%q) = %v, %v", p, eku, err)
		}
	}
	if _, err := PurposeEKU("mtls"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

func TestParseSubject(t *testing.T) {
	if n, err := ParseSubject("web.example.test"); err != nil || n.CommonName != "web.example.test" {
		t.Fatalf("bare CN: %v %v", n, err)
	}
	if n, err := ParseSubject("CN=a,O=b"); err != nil || n.Organization[0] != "b" {
		t.Fatalf("DN: %v %v", n, err)
	}
	for _, bad := range []string{"", "  ", "XX=a"} {
		if _, err := ParseSubject(bad); err == nil {
			t.Errorf("ParseSubject(%q) accepted", bad)
		}
	}
}

func TestWriteIfChanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "f")
	if w, err := writeIfChanged(p, []byte("a"), 0o600); err != nil || !w {
		t.Fatalf("first write %v %v", w, err)
	}
	if w, err := writeIfChanged(p, []byte("a"), 0o600); err != nil || w {
		t.Fatalf("same content rewritten %v %v", w, err)
	}
	wantPrivate(t, p)
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() > 0 { // root ignores directory modes, and Windows (-1) has none
		if _, err := writeIfChanged(filepath.Join(ro, "f"), []byte("a"), 0o600); err == nil {
			t.Fatal("write into a read-only directory succeeded")
		}
	}
}

func TestParseRootErrors(t *testing.T) {
	c, k := selfSigned(t, time.Now().Add(time.Hour), 1)
	keyPEM, _ := plainKeyPEM(k)
	two := append(certPEM(c), certPEM(c)...)
	if _, err := ParseRoot(two, keyPEM, nil); err == nil || !strings.Contains(err.Error(), "want 1") {
		t.Fatalf("two certs: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPEM, _ := plainKeyPEM(other)
	if _, err := ParseRoot(certPEM(c), otherPEM, nil); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	if _, err := ParseRoot(certPEM(c), []byte("junk"), nil); err == nil {
		t.Fatal("junk key accepted")
	}
	if r, err := ParseRoot(certPEM(c), keyPEM, nil); err != nil || r.Cert == nil {
		t.Fatalf("good root: %v", err)
	}
}

func TestLoadIssuerErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	root, rk := selfSigned(t, time.Now().Add(time.Hour), 1)
	rootKey, _ := plainKeyPEM(rk)
	if _, _, err := loadIssuer(write("r.crt", certPEM(root)), write("r.key", rootKey)); err == nil || !strings.Contains(err.Error(), "self-signed root") {
		t.Fatalf("root as issuer: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := plainKeyPEM(other)
	if _, _, err := loadIssuer(write("r.crt", certPEM(root)), write("o.key", otherKey)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched issuer key: %v", err)
	}
	if _, _, err := loadIssuer(filepath.Join(dir, "missing"), write("o.key", otherKey)); err == nil {
		t.Fatal("missing cert accepted")
	}
}

func TestIntermediateRefusesBadExisting(t *testing.T) {
	dir := initRoot(t)
	root, err := LoadRoot(dir, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	w := t.TempDir()
	o := IntermediateOptions{Subject: "CN=Keep", CertOut: filepath.Join(w, "i.crt"), KeyOut: filepath.Join(w, "i.key"),
		Key: KeySpec{Kty: "EC", Crv: "P-256"}, Validity: 24 * time.Hour * 365}
	if _, err := Intermediate(root, o); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(IntermediateOptions) IntermediateOptions{
		"subject":     func(o IntermediateOptions) IntermediateOptions { o.Subject = "CN=Other"; return o },
		"constraints": func(o IntermediateOptions) IntermediateOptions { o.PermittedDNS = []string{"example.test"}; return o },
		"path length": func(o IntermediateOptions) IntermediateOptions { o.PathLen = 1; return o },
		"secret pair": func(o IntermediateOptions) IntermediateOptions { o.SecretOut = "x"; return o },
	} {
		if _, err := Intermediate(root, mutate(o)); err == nil {
			t.Errorf("%s change accepted for an existing intermediate", name)
		}
	}
	// A key that no longer matches the certificate is an error, never replaced.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := plainKeyPEM(other)
	os.WriteFile(o.KeyOut, otherKey, 0o600)
	if _, err := Intermediate(root, o); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched existing key: %v", err)
	}
	// Inside the renewal window it refuses instead of silently re-keying.
	o2 := o
	o2.CertOut, o2.KeyOut = filepath.Join(w, "j.crt"), filepath.Join(w, "j.key")
	if _, err := Intermediate(root, o2); err != nil {
		t.Fatal(err)
	}
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Now().Add(360 * 24 * time.Hour) }
	if _, err := Intermediate(root, o2); err == nil || !strings.Contains(err.Error(), "renewal window") {
		t.Fatalf("near-expiry intermediate: %v", err)
	}
}

func TestLeafSignNoNames(t *testing.T) {
	caCrt, caKey, _ := issuer(t)
	w := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"NoCN"}}}, k)
	csr := filepath.Join(w, "n.csr")
	os.WriteFile(csr, certPEMBytes("CERTIFICATE REQUEST", der), 0o644)
	_, err := LeafSign(LeafSignOptions{CACert: caCrt, CAKey: caKey, CSRPath: csr, CertOut: filepath.Join(w, "n.crt"),
		Validity: time.Hour, Purpose: "server"})
	if err == nil || !strings.Contains(err.Error(), "no SANs") {
		t.Fatalf("CSR without names: %v", err)
	}
	if _, err := LeafSign(LeafSignOptions{CACert: caCrt, CAKey: caKey, CSRPath: csr, DNS: []string{"n.example.test"},
		CertOut: filepath.Join(w, "n.crt"), Validity: time.Hour, Purpose: "nope"}); err == nil {
		t.Fatal("bad purpose accepted")
	}
}

func TestSignCSRErrors(t *testing.T) {
	dir := initRoot(t)
	root, _ := LoadRoot(dir, []byte(testPass))
	w := t.TempDir()
	if _, err := SignCSR(root, SignOptions{CSRPath: filepath.Join(w, "missing.csr"), CertOut: filepath.Join(w, "x")}); err == nil {
		t.Fatal("missing CSR accepted")
	}
	os.WriteFile(filepath.Join(w, "bad.csr"), []byte("not a csr"), 0o644)
	if _, err := SignCSR(root, SignOptions{CSRPath: filepath.Join(w, "bad.csr"), CertOut: filepath.Join(w, "x")}); err == nil {
		t.Fatal("junk CSR accepted")
	}
}

func TestWriteInspectText(t *testing.T) {
	var b strings.Builder
	n := 0
	writeInspectText(&b, &InspectResult{CSR: &CSRView{Subject: "CN=x", Key: "EC P-256", Signature: "ECDSA-SHA256", SignatureValid: false}})
	if !strings.Contains(b.String(), "INVALID") {
		t.Fatalf("CSR text %q", b.String())
	}
	b.Reset()
	writeInspectText(&b, &InspectResult{Certificates: []CertView{{Subject: "CN=a", Expired: true, IsCA: true, PathLen: &n, SelfSigned: true}, {Subject: "CN=b", IsCA: true}}})
	for _, want := range []string{"EXPIRED", "path length 0", "(self-signed)", "path length unlimited", "Certificate 2 of 2"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, b.String())
		}
	}
}

func certPEMBytes(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestIsHostnameAndLeafNames(t *testing.T) {
	for s, want := range map[string]bool{"a.example.test": true, "*.example.test": true, "localhost": true,
		"agent": true, "192.0.2.1": false, "": false, "a b": false, "-a.test": false, "a..test": false, "a.*.test": false} {
		if got := isHostname(s); got != want {
			t.Errorf("isHostname(%q) = %v", s, got)
		}
	}
	e := &env{stderr: &strings.Builder{}}
	dns, ips, rc := leafNames(e, "api.example.test", []string{"192.0.2.40", "api.example.test", "www.example.test"})
	if rc != cont || strings.Join(dns, ",") != "api.example.test,www.example.test" || len(ips) != 1 {
		t.Fatalf("leafNames = %v %v %d", dns, ips, rc)
	}
	if dns, _, _ := leafNames(e, "CN=agent", []string{"agent.example.test"}); strings.Join(dns, ",") != "agent.example.test" {
		t.Fatalf("single-label CN added: %v", dns)
	}
	if _, _, rc := leafNames(e, "CN=Backup Agent", nil); rc != ExitUsage {
		t.Fatal("no names accepted")
	}
}

func TestIsSignerFor(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !isSignerFor(k, k) || isSignerFor(other, k) || isSignerFor("not a key", k) {
		t.Fatal("isSignerFor")
	}
}

// wantPrivate fails unless path is readable by its owner only. Windows has no
// Unix modes, so the check is skipped there.
func wantPrivate(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("%s: want mode 0600, got %v", path, st.Mode().Perm())
	}
}
