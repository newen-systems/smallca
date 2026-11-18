package smallca

import (
	"io"
	"testing"
)

// FuzzParseNotAfter checks durations and times never panic and are positive
// when accepted.
func FuzzParseNotAfter(f *testing.F) {
	for _, s := range []string{"90d", "10y", "36h", "2030-01-01T00:00:00Z", "-1y", "9999999999999y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := ParseNotAfter(s); err == nil && d <= 0 {
			t.Fatalf("ParseNotAfter(%q) = %v", s, d)
		}
	})
}

// FuzzInspect checks inspect never panics on arbitrary input.
func FuzzInspect(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		if res, err := Inspect(b); err == nil {
			writeInspectText(io.Discard, res)
		}
	})
}
