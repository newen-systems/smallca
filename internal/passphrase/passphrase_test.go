package passphrase

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	for in, want := range map[string]string{"s3cret\n": "s3cret", "s3cret\r\n": "s3cret", "a b": "a b"} {
		if got, err := Read(strings.NewReader(in)); err != nil || string(got) != want {
			t.Errorf("Read(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "\n", strings.Repeat("x", MaxBytes+1)} {
		if _, err := Read(strings.NewReader(bad)); err == nil {
			t.Errorf("Read accepted %d bytes", len(bad))
		}
	}
}

func TestFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := FromFile(p); err != nil || string(got) != "s3cret" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := FromFile(p + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestClear(t *testing.T) {
	b := []byte("s3cret")
	Clear(b)
	for _, c := range b {
		if c != 0 {
			t.Fatal("not cleared")
		}
	}
}
