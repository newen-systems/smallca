package certfmt

import (
	"os"
	"path/filepath"
	"testing"
)

func seed(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
}

// FuzzDecodeCerts checks the certificate decoder never panics and never
// returns an empty success.
func FuzzDecodeCerts(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		ders, err := DecodeCerts(b)
		if err == nil && len(ders) == 0 {
			t.Fatal("no error and no certificates")
		}
		for _, d := range ders {
			if len(d) == 0 {
				t.Fatal("no error and an empty certificate")
			}
		}
	})
}

// FuzzDecodeCSR checks the CSR decoder never panics and never returns empty DER.
func FuzzDecodeCSR(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		der, err := DecodeCSR(b)
		if err == nil && len(der) == 0 {
			t.Fatal("no error and empty DER")
		}
	})
}
