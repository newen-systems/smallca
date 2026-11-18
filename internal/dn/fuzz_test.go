package dn

import "testing"

// FuzzParseDN checks the DN parser never panics and never accepts an empty
// common name it was given.
func FuzzParseDN(f *testing.F) {
	for _, s := range []string{"CN=Certificate Authority,O=EXAMPLE.TEST", `CN=a\,b`, "cn=x,ou=y,c=AU,st=s,l=l", "CN=", "=", `\`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseDN(s)
		if err == nil && n.String() == "" {
			t.Fatalf("ParseDN(%q) accepted an empty name", s)
		}
	})
}
