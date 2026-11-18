package smallca

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPass = "correct horse battery staple"

// run invokes the CLI and decodes stdout JSON into a map.
func run(t *testing.T, stdin string, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(args, strings.NewReader(stdin), &out, &errb)
	var m map[string]any
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("stdout is not JSON: %v: %q", err, out.String())
		}
	}
	return rc, m, errb.String()
}

func mustRun(t *testing.T, stdin string, args ...string) map[string]any {
	t.Helper()
	rc, m, stderr := run(t, stdin, args...)
	if rc != 0 {
		t.Fatalf("smallca %v: rc=%d stderr=%s", args[0], rc, stderr)
	}
	return m
}

func initRoot(t *testing.T, args ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	m := mustRun(t, testPass+"\n", append([]string{"root", "create", "--root-dir", dir, "--subject", "CN=Test Root CA,O=Example", "--password-stdin"}, args...)...)
	if m["changed"] != true {
		t.Fatalf("first init changed=%v", m["changed"])
	}
	return dir
}

func needOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
}

func openssl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("openssl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// freeipaCSR writes a CSR shaped like the one ipa-server-install --external-ca
// emits: RSA, subject O=REALM then CN=Certificate Authority (UTF8String, as
// NSS/openssl encode it), and critical basicConstraints and keyUsage requests.
func freeipaCSR(t *testing.T, dir, name string) string {
	t.Helper()
	needOpenSSL(t)
	csr := filepath.Join(dir, name+".csr")
	openssl(t, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(dir, name+".key"),
		"-subj", "/O=EXAMPLE.TEST/CN=Certificate Authority", "-utf8",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-out", csr)
	return csr
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d": 90 * 24 * time.Hour, "10y": 10 * 365 * 24 * time.Hour, "36h": 36 * time.Hour,
	} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0d", "-1y", "xd", "ten", "300y", "9999999999999d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
}

func TestInitIdempotentAndEncrypted(t *testing.T) {
	dir := initRoot(t)
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "root.key"))
	if !bytes.Contains(keyPEM, []byte("ENCRYPTED PRIVATE KEY")) {
		t.Fatal("root key is not encrypted PKCS#8")
	}
	wantPrivate(t, filepath.Join(dir, "root.key"))
	before, _ := os.ReadFile(filepath.Join(dir, "root.crt"))
	m := mustRun(t, testPass, "root", "create", "--root-dir", dir, "--subject", "CN=Test Root CA,O=Example", "--password-stdin")
	after, _ := os.ReadFile(filepath.Join(dir, "root.crt"))
	if m["changed"] != false || !bytes.Equal(before, after) {
		t.Fatal("second init changed the root")
	}
	if rc, _, _ := run(t, "wrong", "root", "create", "--root-dir", dir, "--subject", "CN=Test Root CA,O=Example", "--password-stdin"); rc != 1 {
		t.Fatalf("wrong passphrase rc=%d, want 1", rc)
	}
	if rc, _, _ := run(t, testPass, "root", "create", "--root-dir", dir, "--subject", "CN=Other Root", "--password-stdin"); rc != 1 {
		t.Fatalf("different subject rc=%d, want 1", rc)
	}
	root, _ := readCert(filepath.Join(dir, "root.crt"))
	if !root.IsCA || root.MaxPathLen != 2 || root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("root profile: ca=%v pathlen=%d ku=%v", root.IsCA, root.MaxPathLen, root.KeyUsage)
	}
}

// TestSignFreeIPACSR is the FreeIPA contract: subject DER preserved, CA profile
// applied, and the cert + chain files verify with openssl the way
// ipa-server-install consumes them.
func TestSignFreeIPACSR(t *testing.T) {
	dir := initRoot(t)
	work := t.TempDir()
	csr := freeipaCSR(t, work, "ipa")
	cert, chain, full := filepath.Join(work, "ipa.crt"), filepath.Join(work, "ipa-chain.pem"), filepath.Join(work, "ipa-full.pem")
	args := []string{"intermediate", "sign", "--root-dir", dir, "--csr", csr, "--cert-out", cert, "--chain-out", chain, "--fullchain-out", full, "--password-stdin"}
	m := mustRun(t, testPass, args...)
	if m["changed"] != true || m["subject"] != "CN=Certificate Authority,O=EXAMPLE.TEST" {
		t.Fatalf("sign output %v", m)
	}

	issued, err := readCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, _ := os.ReadFile(csr)
	block, _ := pem.Decode(csrDER)
	req, _ := x509.ParseCertificateRequest(block.Bytes)
	if !bytes.Equal(issued.RawSubject, req.RawSubject) {
		t.Fatal("issued subject DER differs from CSR subject DER")
	}
	if !issued.IsCA || !issued.MaxPathLenZero || issued.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("issued profile: ca=%v pathlen0=%v ku=%v", issued.IsCA, issued.MaxPathLenZero, issued.KeyUsage)
	}
	if len(issued.SubjectKeyId) == 0 || len(issued.AuthorityKeyId) == 0 {
		t.Fatal("issued cert lacks SKI or AKI")
	}
	if certs, _ := readCerts(chain); len(certs) != 1 || certs[0].CheckSignatureFrom(certs[0]) != nil {
		t.Fatal("chain file is not exactly the self-signed root")
	}
	if certs, _ := readCerts(full); len(certs) != 2 || !bytes.Equal(certs[0].Raw, issued.Raw) {
		t.Fatal("fullchain is not cert then root")
	}
	openssl(t, "verify", "-x509_strict", "-CAfile", chain, cert)
	openssl(t, "verify", "-CAfile", filepath.Join(dir, "root.crt"), full)

	// Idempotent re-run keeps the same cert.
	m = mustRun(t, testPass, args...)
	if m["changed"] != false {
		t.Fatal("re-sign of same CSR changed files")
	}
	// A new CSR (reinstall) re-signs.
	csr2 := freeipaCSR(t, work, "ipa2")
	args[5] = csr2
	m = mustRun(t, testPass, args...)
	if m["changed"] != true {
		t.Fatal("new CSR did not re-sign")
	}
	// Changing the profile re-signs too.
	m = mustRun(t, testPass, append(args, "--path-len", "1")...)
	if m["changed"] != true {
		t.Fatal("path-len change did not re-sign")
	}
	// A path length the root cannot allow is refused.
	if rc, _, stderr := run(t, testPass, append(args, "--path-len", "2")...); rc != 1 || !strings.Contains(stderr, "path length") {
		t.Fatalf("path-len 2 under root path-len 2: rc=%d stderr=%s", rc, stderr)
	}
	// smallca verify agrees with openssl.
	m = mustRun(t, "", "certificate", "verify", "--roots", filepath.Join(dir, "root.crt"), "--cert", cert)
	if m["valid"] != true {
		t.Fatalf("verify %v", m)
	}
}

func TestIntermediateLeafAndSecret(t *testing.T) {
	dir := initRoot(t)
	out := filepath.Join(dir, "k8s")
	args := []string{"intermediate", "create", "--root-dir", dir, "--subject", "CN=K8s Issuing CA,O=Example",
		"--cert-out", filepath.Join(out, "k8s.crt"), "--key-out", filepath.Join(out, "k8s.key"), "--fullchain-out", filepath.Join(out, "k8s-fullchain.pem"),
		"--permitted-dns", "example.test", "--k8s-secret-out", filepath.Join(out, "k8s-secret.yaml"), "--k8s-secret-name", "ca-key-pair",
		"--k8s-secret-namespace", "cert-manager", "--password-stdin"}
	m := mustRun(t, testPass, args...)
	if m["changed"] != true {
		t.Fatal("intermediate not created")
	}
	wantPrivate(t, filepath.Join(out, "k8s.key"))
	secret, _ := os.ReadFile(filepath.Join(out, "k8s-secret.yaml"))
	for _, want := range []string{"type: kubernetes.io/tls", "name: \"ca-key-pair\"", "namespace: \"cert-manager\"", "tls.crt: ", "tls.key: ", "ca.crt: "} {
		if !bytes.Contains(secret, []byte(want)) {
			t.Errorf("secret YAML lacks %q", want)
		}
	}
	if m = mustRun(t, testPass, args...); m["changed"] != false {
		t.Fatal("intermediate re-run changed files")
	}
	// A different subject for the existing name is refused, not replaced.
	bad := append([]string{}, args...)
	bad[5] = "CN=Other"
	if rc, _, _ := run(t, testPass, bad...); rc != 1 {
		t.Fatalf("subject change rc=%d, want 1", rc)
	}

	work := t.TempDir()
	leafArgs := []string{"leaf", "create", "--issuer-cert", filepath.Join(out, "k8s.crt"), "--issuer-key", filepath.Join(out, "k8s.key"),
		"--subject", "web.example.test", "--san", "web.example.test,www.example.test", "--san", "192.0.2.5",
		"--cert-out", filepath.Join(work, "web.crt"), "--key-out", filepath.Join(work, "web.key"), "--fullchain-out", filepath.Join(work, "web-fullchain.pem")}
	if m = mustRun(t, "", leafArgs...); m["changed"] != true {
		t.Fatal("leaf not issued")
	}
	if m = mustRun(t, "", leafArgs...); m["changed"] != false {
		t.Fatal("leaf re-run changed files")
	}
	m = mustRun(t, "", "certificate", "verify", "--roots", filepath.Join(dir, "root.crt"), "--cert", filepath.Join(work, "web-fullchain.pem"), "--host", "www.example.test")
	if m["valid"] != true || len(m["chain"].([]any)) != 3 {
		t.Fatalf("leaf verify %v", m)
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		openssl(t, "verify", "-CAfile", filepath.Join(dir, "root.crt"), "-untrusted", filepath.Join(out, "k8s-fullchain.pem"), filepath.Join(work, "web.crt"))
	}
	// Name constraints bite: a leaf outside example.test does not verify.
	if m = mustRun(t, "", "leaf", "create", "--issuer-cert", filepath.Join(out, "k8s.crt"), "--issuer-key", filepath.Join(out, "k8s.key"),
		"--subject", "evil.other", "--cert-out", filepath.Join(work, "evil.crt"), "--key-out", filepath.Join(work, "evil.key")); m["changed"] != true {
		t.Fatal("evil leaf not issued")
	}
	rc, m, _ := run(t, "", "certificate", "verify", "--roots", filepath.Join(dir, "root.crt"), "--cert", filepath.Join(work, "evil.crt"), "--chain", filepath.Join(out, "k8s-fullchain.pem"))
	if rc != ExitInvalid || m["valid"] != false {
		t.Fatalf("name-constrained verify rc=%d %v", rc, m)
	}
	// Leaves never come straight from the root.
	if rc, _, _ := run(t, "", "leaf", "create", "--issuer-cert", filepath.Join(dir, "root.crt"), "--issuer-key", filepath.Join(out, "k8s.key"),
		"--subject", "x.example.test", "--cert-out", filepath.Join(work, "x.crt"), "--key-out", filepath.Join(work, "x.key")); rc != 1 {
		t.Fatalf("leaf from root rc=%d, want 1", rc)
	}
}

func TestVerifyWrongRoot(t *testing.T) {
	a, b := initRoot(t), initRoot(t)
	rc, m, _ := run(t, "", "certificate", "verify", "--roots", filepath.Join(b, "root.crt"), "--cert", filepath.Join(a, "root.crt"))
	if rc != ExitInvalid || m["valid"] != false || m["error"] == "" {
		t.Fatalf("wrong root rc=%d %v", rc, m)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, "no command given"},
		{[]string{"bogus"}, "unknown command"},
		{[]string{"root", "bogus"}, "unknown command"},
		{[]string{"intermediate", "sign"}, "--csr, --cert-out"},
		{[]string{"root", "create", "--root-dir", "x", "--subject", "CN=x"}, "exactly one of --password-file"},
		{[]string{"root", "create", "--root-dir", "x", "--subject", "CN=x", "--password-stdin", "--password-file", "f"}, "exactly one of"},
		{[]string{"root", "create", "--root-dir", "x", "--subject", "CN=x", "--not-after", "0d", "--password-stdin"}, "must be positive"},
		{[]string{"root", "create", "--root-dir", "x", "--subject", "CN=x", "--kty", "RSA", "--crv", "P-256", "--password-stdin"}, "--crv applies"},
		{[]string{"root", "create", "--root-dir", "x", "--subject", "CN=x", "--crv", "P-521", "--password-stdin"}, "unsupported --crv"},
		{[]string{"certificate", "verify", "--roots", "a", "--cert", "b", "extra"}, "unexpected arguments"},
		{[]string{"leaf", "create"}, "--issuer-cert, --issuer-key, --subject, --cert-out, --key-out"},
		{[]string{"intermediate", "create"}, "--subject, --cert-out, --key-out"},
		{[]string{"leaf", "create", "--nope"}, "flag provided but not defined"},
	}
	for _, c := range cases {
		rc, _, stderr := run(t, testPass, c.args...)
		if rc != ExitUsage || !strings.Contains(stderr, c.want) || !strings.Contains(stderr, `"code":"usage"`) {
			t.Errorf("%v: rc=%d stderr=%q, want rc 2 containing %q", c.args, rc, stderr, c.want)
		}
	}
	if rc, m, _ := run(t, "", "version"); rc != 0 || m["version"] == nil || m["schema_version"] != float64(1) {
		t.Errorf("version rc=%d %v", rc, m)
	}
	for _, args := range [][]string{{"help"}, {"--help"}, {"help", "leaf", "create"}, {"leaf", "create", "--help"}} {
		var out bytes.Buffer
		if rc := Run(args, nil, &out, &out); rc != 0 || !strings.Contains(out.String(), "leaf create") {
			t.Errorf("%v rc=%d", args, rc)
		}
	}
}

func TestQuietAndPasswordFile(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(testPass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ca")
	var out, errb bytes.Buffer
	if rc := Run([]string{"root", "create", "--root-dir", dir, "--subject", "CN=Q", "--kty", "RSA", "--size", "2048", "--password-file", pw, "--quiet"}, nil, &out, &errb); rc != 0 || out.Len() != 0 {
		t.Fatalf("quiet rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	root, err := LoadRoot(dir, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := root.Key.Public().(*rsa.PublicKey); !ok {
		t.Fatalf("root key %T, want RSA", root.Key.Public())
	}
}

func TestParseNotAfter(t *testing.T) {
	if d, err := ParseNotAfter(time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)); err != nil || d < 47*time.Hour {
		t.Fatalf("RFC 3339 not-after: %v %v", d, err)
	}
	if _, err := ParseNotAfter("2001-01-01T00:00:00Z"); err == nil {
		t.Fatal("past not-after accepted")
	}
}

func TestInspect(t *testing.T) {
	dir := initRoot(t)
	work := t.TempDir()
	mustRun(t, testPass, "intermediate", "create", "--root-dir", dir, "--subject", "CN=Inspect CA", "--permitted-dns", "example.test",
		"--cert-out", filepath.Join(work, "ca.crt"), "--key-out", filepath.Join(work, "ca.key"), "--password-stdin")
	mustRun(t, "", "leaf", "create", "--issuer-cert", filepath.Join(work, "ca.crt"), "--issuer-key", filepath.Join(work, "ca.key"),
		"--subject", "a.example.test", "--san", "a.example.test,192.0.2.9", "--purpose", "both",
		"--cert-out", filepath.Join(work, "a.crt"), "--key-out", filepath.Join(work, "a.key"), "--fullchain-out", filepath.Join(work, "a-full.pem"))

	m := mustRun(t, "", "certificate", "inspect", "--file", filepath.Join(work, "a-full.pem"), "--json")
	certs := m["certificates"].([]any)
	leaf, ca := certs[0].(map[string]any), certs[1].(map[string]any)
	if len(certs) != 2 || leaf["subject"] != "CN=a.example.test" || leaf["is_ca"] != false ||
		fmt.Sprint(leaf["ip_addresses"]) != "[192.0.2.9]" || fmt.Sprint(leaf["ext_key_usage"]) != "[serverAuth clientAuth]" {
		t.Fatalf("leaf view %v", leaf)
	}
	if ca["is_ca"] != true || ca["path_len"] != float64(0) || fmt.Sprint(ca["permitted_dns"]) != "[example.test]" {
		t.Fatalf("CA view %v", ca)
	}

	var out, errb bytes.Buffer
	data, _ := os.ReadFile(filepath.Join(work, "a.crt"))
	if rc := Run([]string{"certificate", "inspect", "--file", "-"}, bytes.NewReader(data), &out, &errb); rc != 0 ||
		!strings.Contains(out.String(), "Ext key usage:   serverAuth, clientAuth") || !strings.Contains(out.String(), "days left") {
		t.Fatalf("text inspect rc=%d out=%s err=%s", rc, out.String(), errb.String())
	}

	if rc, _, stderr := run(t, "", "certificate", "inspect", "--file", filepath.Join(work, "a.key")); rc != 1 || !strings.Contains(stderr, "private key") {
		t.Fatalf("key inspect rc=%d stderr=%s", rc, stderr)
	}
}

func TestInspectCSR(t *testing.T) {
	work := t.TempDir()
	csr := freeipaCSR(t, work, "ipa")
	m := mustRun(t, "", "certificate", "inspect", "--file", csr, "--json")
	r := m["csr"].(map[string]any)
	if r["subject"] != "CN=Certificate Authority,O=EXAMPLE.TEST" || r["signature_valid"] != true || r["key"] != "RSA 2048" {
		t.Fatalf("csr view %v", r)
	}
}

// TestShortLivedLeafIsIdempotent: a leaf shorter than the 30-day window must
// not be re-issued on every run.
func TestShortLivedLeafIsIdempotent(t *testing.T) {
	dir := initRoot(t)
	work := t.TempDir()
	mustRun(t, testPass, "intermediate", "create", "--root-dir", dir, "--subject", "CN=Short CA",
		"--cert-out", filepath.Join(work, "ca.crt"), "--key-out", filepath.Join(work, "ca.key"), "--password-stdin")
	args := []string{"leaf", "create", "--issuer-cert", filepath.Join(work, "ca.crt"), "--issuer-key", filepath.Join(work, "ca.key"),
		"--subject", "s.example.test", "--not-after", "7d", "--cert-out", filepath.Join(work, "s.crt"), "--key-out", filepath.Join(work, "s.key")}
	mustRun(t, "", args...)
	if m := mustRun(t, "", args...); m["changed"] != false {
		t.Fatal("7-day leaf re-issued on the second run")
	}
	// Six days later it is inside the last third of its lifetime and renews.
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Now().Add(6 * 24 * time.Hour) }
	if m := mustRun(t, "", args...); m["changed"] != true {
		t.Fatal("7-day leaf not renewed in its last third")
	}
}

// TestRootFromPipe signs with a root read from explicit paths (here stdin for
// the key, as from a secret manager), with and without encryption.
func TestRootFromPipe(t *testing.T) {
	dir := initRoot(t)
	certPath, keyPath := RootPaths(dir)
	enc, _ := os.ReadFile(keyPath)
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte(testPass), 0o600)
	work := t.TempDir()
	base := []string{"intermediate", "create", "--root-cert", certPath, "--root-key", "-", "--subject", "CN=Piped CA",
		"--cert-out", filepath.Join(work, "p.crt"), "--key-out", filepath.Join(work, "p.key")}
	if m := mustRun(t, string(enc), append(base, "--password-file", pw)...); m["changed"] != true {
		t.Fatal("encrypted piped root did not sign")
	}
	if rc, _, stderr := run(t, string(enc), base...); rc != ExitUsage || !strings.Contains(stderr, "encrypted") {
		t.Fatalf("encrypted key without password rc=%d %s", rc, stderr)
	}
	root, err := LoadRoot(dir, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := plainKeyPEM(root.Key)
	if m := mustRun(t, string(plain), base...); m["changed"] != false {
		t.Fatalf("clear piped root re-run %v", m)
	}
	if rc, _, stderr := run(t, string(plain), append(base, "--password-file", pw)...); rc != ExitUsage || !strings.Contains(stderr, "not encrypted") {
		t.Fatalf("clear key with password rc=%d %s", rc, stderr)
	}
	if rc, _, stderr := run(t, testPass, append(base, "--password-stdin")...); rc != ExitUsage || !strings.Contains(stderr, "both read stdin") {
		t.Fatalf("double stdin rc=%d %s", rc, stderr)
	}
	if rc, _, _ := run(t, "", "intermediate", "create", "--root-dir", dir, "--root-cert", certPath, "--subject", "CN=x",
		"--cert-out", "x", "--key-out", "y"); rc != ExitUsage {
		t.Fatal("--root-dir with --root-cert accepted")
	}
}

func TestInspectURL(t *testing.T) {
	dir := initRoot(t)
	work := t.TempDir()
	mustRun(t, testPass, "intermediate", "create", "--root-dir", dir, "--subject", "CN=TLS CA",
		"--cert-out", filepath.Join(work, "ca.crt"), "--key-out", filepath.Join(work, "ca.key"), "--password-stdin")
	mustRun(t, "", "leaf", "create", "--issuer-cert", filepath.Join(work, "ca.crt"), "--issuer-key", filepath.Join(work, "ca.key"),
		"--subject", "srv.example.test", "--cert-out", filepath.Join(work, "s.crt"), "--key-out", filepath.Join(work, "s.key"),
		"--fullchain-out", filepath.Join(work, "s-full.pem"))
	pair, err := tls.LoadX509KeyPair(filepath.Join(work, "s-full.pem"), filepath.Join(work, "s.key"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	m := mustRun(t, "", "certificate", "inspect", "--url", "https://"+ln.Addr().String(), "--servername", "srv.example.test", "--json")
	certs := m["certificates"].([]any)
	if len(certs) != 2 || certs[0].(map[string]any)["subject"] != "CN=srv.example.test" {
		t.Fatalf("fetched chain %v", m)
	}
	if rc, _, _ := run(t, "", "certificate", "inspect", "--url", "127.0.0.1:1"); rc != ExitError {
		t.Fatalf("closed port rc=%d", rc)
	}
	if rc, _, _ := run(t, "", "certificate", "inspect", "--url", "x", "--cert", "y"); rc != ExitUsage {
		t.Fatalf("both sources rc=%d", rc)
	}
}

// issuer creates a root and an intermediate and returns the intermediate's
// cert and key paths and the root cert path.
func issuer(t *testing.T) (caCrt, caKey, rootCrt string) {
	t.Helper()
	dir := initRoot(t)
	work := t.TempDir()
	caCrt, caKey = filepath.Join(work, "ca.crt"), filepath.Join(work, "ca.key")
	mustRun(t, testPass, "intermediate", "create", "--root-dir", dir, "--subject", "CN=Tools CA",
		"--cert-out", caCrt, "--key-out", caKey, "--password-stdin")
	return caCrt, caKey, filepath.Join(dir, "root.crt")
}

func TestCSRCreateAndLeafSign(t *testing.T) {
	caCrt, caKey, rootCrt := issuer(t)
	w := t.TempDir()
	key, csr, crt := filepath.Join(w, "app.key"), filepath.Join(w, "app.csr"), filepath.Join(w, "app.crt")
	csrArgs := []string{"csr", "create", "--subject", "CN=app.example.test,O=Example", "--san", "app.example.test,192.0.2.30",
		"--key-out", key, "--csr-out", csr}
	if m := mustRun(t, "", csrArgs...); m["changed"] != true {
		t.Fatal("csr not created")
	}
	before, _ := os.ReadFile(csr)
	if m := mustRun(t, "", csrArgs...); m["changed"] != false {
		t.Fatal("csr re-run changed")
	}
	if after, _ := os.ReadFile(csr); !bytes.Equal(before, after) {
		t.Fatal("csr rewritten")
	}
	signArgs := []string{"leaf", "sign", "--issuer-cert", caCrt, "--issuer-key", caKey, "--csr", csr, "--cert-out", crt,
		"--fullchain-out", filepath.Join(w, "app-full.pem")}
	m := mustRun(t, "", signArgs...)
	if m["changed"] != true || m["subject"] != "CN=app.example.test,O=Example" ||
		fmt.Sprint(m["dns_names"]) != "[app.example.test]" || fmt.Sprint(m["ip_addresses"]) != "[192.0.2.30]" {
		t.Fatalf("leaf sign %v", m)
	}
	if m = mustRun(t, "", signArgs...); m["changed"] != false {
		t.Fatal("leaf sign re-run changed")
	}
	if m = mustRun(t, "", append(signArgs, "--san", "other.example.test")...); m["changed"] != true || fmt.Sprint(m["dns_names"]) != "[other.example.test]" {
		t.Fatalf("--san override %v", m)
	}
	m = mustRun(t, "", "certificate", "match", "--cert", crt, "--key", key, "--csr", csr)
	if m["match"] != true {
		t.Fatalf("match %v", m)
	}
	m = mustRun(t, "", "certificate", "verify", "--roots", rootCrt, "--cert", filepath.Join(w, "app-full.pem"), "--host", "other.example.test")
	if m["valid"] != true {
		t.Fatalf("verify %v", m)
	}
}

func TestMatchMismatch(t *testing.T) {
	caCrt, caKey, _ := issuer(t)
	if rc, m, _ := run(t, "", "certificate", "match", "--cert", caCrt, "--key", caKey); rc != 0 || m["match"] != true {
		t.Fatalf("matching pair rc=%d %v", rc, m)
	}
	w := t.TempDir()
	mustRun(t, "", "csr", "create", "--subject", "x.example.test", "--key-out", filepath.Join(w, "x.key"), "--csr-out", filepath.Join(w, "x.csr"))
	rc, m, _ := run(t, "", "certificate", "match", "--cert", caCrt, "--key", filepath.Join(w, "x.key"))
	if rc != ExitInvalid || m["match"] != false || m["mismatch"] == "" {
		t.Fatalf("mismatch rc=%d %v", rc, m)
	}
	if rc, _, _ := run(t, "", "certificate", "match", "--cert", caCrt); rc != ExitError {
		t.Fatalf("one input rc=%d", rc)
	}
}

func TestVerifyMinRemaining(t *testing.T) {
	caCrt, caKey, rootCrt := issuer(t)
	w := t.TempDir()
	crt := filepath.Join(w, "s.crt")
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "s.example.test", "--not-after", "10d",
		"--cert-out", crt, "--key-out", filepath.Join(w, "s.key"))
	if m := mustRun(t, "", "certificate", "verify", "--cert", crt, "--min-remaining", "5d"); m["valid"] != true {
		t.Fatalf("expiry-only check %v", m)
	}
	rc, m, _ := run(t, "", "certificate", "verify", "--cert", crt, "--chain", caCrt, "--roots", rootCrt, "--min-remaining", "30d")
	if rc != ExitInvalid || !strings.Contains(fmt.Sprint(m["error"]), "less than the required") {
		t.Fatalf("min-remaining rc=%d %v", rc, m)
	}
	if rc, _, _ := run(t, "", "certificate", "verify", "--cert", crt); rc != ExitUsage {
		t.Fatalf("no roots and no min-remaining rc=%d", rc)
	}
}

func TestBundle(t *testing.T) {
	caCrt, caKey, rootCrt := issuer(t)
	w := t.TempDir()
	crt := filepath.Join(w, "b.crt")
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "b.example.test", "--cert-out", crt, "--key-out", filepath.Join(w, "b.key"))
	out := filepath.Join(w, "full.pem")
	// Out of order, with a duplicate.
	m := mustRun(t, "", "certificate", "bundle", "--cert", rootCrt, "--cert", caCrt, "--cert", crt, "--cert", caCrt, "--fullchain-out", out)
	if m["changed"] != true || m["ends_at_root"] != true || fmt.Sprint(m["chain"]) != "[CN=b.example.test CN=Tools CA]" {
		t.Fatalf("bundle %v", m)
	}
	if m = mustRun(t, "", "certificate", "bundle", "--cert", crt, "--cert", caCrt, "--cert", rootCrt, "--fullchain-out", out); m["changed"] != false {
		t.Fatal("bundle re-run changed")
	}
	if m = mustRun(t, "", "certificate", "bundle", "--cert", crt, "--cert", caCrt, "--cert", rootCrt, "--fullchain-out", out, "--include-root"); len(m["chain"].([]any)) != 3 {
		t.Fatalf("include-root %v", m)
	}
	// Two unrelated chains are refused.
	other, _, _ := issuer(t)
	if rc, _, stderr := run(t, "", "certificate", "bundle", "--cert", crt, "--cert", caCrt, "--cert", other, "--fullchain-out", out); rc != ExitError || !strings.Contains(stderr, "more than one chain") {
		t.Fatalf("two chains rc=%d %s", rc, stderr)
	}
}

func TestConvertToP12(t *testing.T) {
	caCrt, caKey, _ := issuer(t)
	w := t.TempDir()
	crt, key := filepath.Join(w, "e.crt"), filepath.Join(w, "e.key")
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "e.example.test", "--cert-out", crt, "--key-out", key)
	pw := filepath.Join(w, "pw")
	os.WriteFile(pw, []byte("pfx-pass\n"), 0o600)
	out := filepath.Join(w, "e.pfx")
	args := []string{"certificate", "convert", "--in", crt, "--in", key, "--in", caCrt, "--p12-out", out, "--password-file", pw}
	if m := mustRun(t, "", args...); m["changed"] != true || len(m["certificates"].([]any)) != 2 {
		t.Fatalf("p12 %v", m)
	}
	if m := mustRun(t, "", args...); m["changed"] != false {
		t.Fatal("export re-run changed")
	}
	wantPrivate(t, out)
	if _, err := exec.LookPath("openssl"); err == nil {
		openssl(t, "pkcs12", "-in", out, "-passin", "pass:pfx-pass", "-noout")
	}
	if m := mustRun(t, "", append(args, "--legacy")...); m["changed"] != false {
		t.Fatal("legacy re-run of an equal file changed it")
	}
}

// mtlsPair issues a server and a client leaf from one intermediate.
func mtlsPair(t *testing.T, clientPurpose string) (w, rootCrt string) {
	t.Helper()
	caCrt, caKey, rootCrt := issuer(t)
	w = t.TempDir()
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "api.example.test", "--purpose", "server",
		"--cert-out", filepath.Join(w, "server.crt"), "--key-out", filepath.Join(w, "server.key"), "--fullchain-out", filepath.Join(w, "server-full.pem"))
	mustRun(t, "", "leaf", "create", "--issuer-cert", caCrt, "--issuer-key", caKey, "--subject", "CN=agent", "--san", "agent.example.test", "--purpose", clientPurpose,
		"--cert-out", filepath.Join(w, "client.crt"), "--key-out", filepath.Join(w, "client.key"), "--fullchain-out", filepath.Join(w, "client-full.pem"))
	return w, rootCrt
}

func TestMTLSOffline(t *testing.T) {
	w, root := mtlsPair(t, "client")
	args := []string{"mtls", "verify", "--server-cert", filepath.Join(w, "server-full.pem"), "--server-key", filepath.Join(w, "server.key"),
		"--server-trust", root, "--client-cert", filepath.Join(w, "client-full.pem"), "--client-key", filepath.Join(w, "client.key"),
		"--client-trust", root, "--host", "api.example.test"}
	if m := mustRun(t, "", args...); m["valid"] != true || len(m["checks"].([]any)) != 4 {
		t.Fatalf("good pair %v", m)
	}
	// The wrong host name fails only the server check.
	bad := append(append([]string{}, args[:len(args)-1]...), "other.example.test")
	if rc, m, _ := run(t, "", bad...); rc != ExitInvalid || m["valid"] != false {
		t.Fatalf("wrong host rc=%d %v", rc, m)
	}
	// A server-only certificate used as a client is caught.
	w2, root2 := mtlsPair(t, "server")
	rc, m, _ := run(t, "", "mtls", "verify", "--server-cert", filepath.Join(w2, "server-full.pem"), "--server-trust", root2,
		"--client-cert", filepath.Join(w2, "client-full.pem"), "--client-trust", root2)
	checks := m["checks"].([]any)
	if rc != ExitInvalid || checks[0].(map[string]any)["ok"] != true || checks[1].(map[string]any)["ok"] != false {
		t.Fatalf("server-purpose client rc=%d %v", rc, m)
	}
	// Trusting the wrong CA is caught.
	_, _, otherRoot := issuer(t)
	if rc, _, _ := run(t, "", "mtls", "verify", "--server-cert", filepath.Join(w, "server-full.pem"), "--server-trust", otherRoot,
		"--client-cert", filepath.Join(w, "client-full.pem"), "--client-trust", root); rc != ExitInvalid {
		t.Fatalf("wrong server trust rc=%d", rc)
	}
}

func TestMTLSLive(t *testing.T) {
	w, root := mtlsPair(t, "client")
	pair, err := tls.LoadX509KeyPair(filepath.Join(w, "server-full.pem"), filepath.Join(w, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, _ := os.ReadFile(root)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if c.(*tls.Conn).Handshake() == nil {
					time.Sleep(3 * time.Second) // hold the connection like a server awaiting a request
				}
			}(c)
		}
	}()
	live := []string{"mtls", "verify", "--url", ln.Addr().String(), "--servername", "api.example.test",
		"--client-cert", filepath.Join(w, "client-full.pem"), "--client-key", filepath.Join(w, "client.key"), "--client-trust", root}
	if m := mustRun(t, "", live...); m["valid"] != true {
		t.Fatalf("live accepted %v", m)
	}
	// A client certificate from another CA is rejected by the server.
	w2, _ := mtlsPair(t, "client")
	bad := append([]string{}, live...)
	bad[7], bad[9] = filepath.Join(w2, "client-full.pem"), filepath.Join(w2, "client.key")
	rc, m, _ := run(t, "", bad...)
	if rc != ExitInvalid || m["valid"] != false {
		t.Fatalf("live rejected rc=%d %v", rc, m)
	}
}

// TestDryRun: --dry-run reports the change it would make and writes nothing.
func TestDryRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	args := []string{"root", "create", "--root-dir", dir, "--subject", "CN=Dry", "--password-stdin"}
	m := mustRun(t, testPass, append(args, "--dry-run")...)
	if m["changed"] != true || m["dry_run"] != true {
		t.Fatalf("dry run %v", m)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dry run created the root directory")
	}
	mustRun(t, testPass, args...)
	w := t.TempDir()
	leaf := []string{"intermediate", "create", "--root-dir", dir, "--subject", "CN=Dry CA", "--password-stdin",
		"--cert-out", filepath.Join(w, "i.crt"), "--key-out", filepath.Join(w, "i.key")}
	if m = mustRun(t, testPass, append(leaf, "--dry-run")...); m["changed"] != true {
		t.Fatal("dry run of a new intermediate reported no change")
	}
	if entries, _ := os.ReadDir(w); len(entries) != 0 {
		t.Fatalf("dry run wrote %d files", len(entries))
	}
	mustRun(t, testPass, leaf...)
	if m = mustRun(t, testPass, append(leaf, "--dry-run")...); m["changed"] != false {
		t.Fatal("dry run of an existing intermediate reported a change")
	}
	if m = mustRun(t, testPass, args...); m["dry_run"] != nil {
		t.Fatal("dry_run leaked into a later run")
	}
}
