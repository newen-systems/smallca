package csrutil

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseCSR checks the strict CSR parser never panics and that anything it
// accepts has a valid signature.
func FuzzParseCSR(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("..", "certfmt", "testdata", "csr_*"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		csr, err := ParseCSR(b)
		if err != nil {
			return
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("accepted a CSR with a bad signature: %v", err)
		}
	})
}
