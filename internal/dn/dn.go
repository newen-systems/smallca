// Package dn parses a subset of RFC 2253 distinguished names into a pkix.Name.
// It uses the standard library only.
package dn

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

// ParseDN parses a distinguished name such as "CN=Certificate Authority,O=EXAMPLE.TEST"
// into a pkix.Name. Only the CN, O, OU, C, ST, and L attribute types are
// supported (case-insensitive); any other type is an error, as is an empty
// value. RDNs are separated by unescaped commas: a backslash escapes the next
// character, so `CN=a\,b` yields a single CN with the literal value "a,b".
func ParseDN(s string) (pkix.Name, error) {
	var name pkix.Name
	for _, rdn := range splitUnescaped(s, ',') {
		eq := strings.IndexByte(rdn, '=')
		if eq < 0 {
			return pkix.Name{}, fmt.Errorf("dn: %q is not attribute=value", rdn)
		}
		attr := strings.ToUpper(strings.TrimSpace(rdn[:eq]))
		value := unescape(rdn[eq+1:])
		if value == "" {
			return pkix.Name{}, fmt.Errorf("dn: attribute %q has empty value", attr)
		}
		switch attr {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = append(name.Organization, value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "C":
			name.Country = append(name.Country, value)
		case "ST":
			name.Province = append(name.Province, value)
		case "L":
			name.Locality = append(name.Locality, value)
		default:
			return pkix.Name{}, fmt.Errorf("dn: unsupported attribute %q", attr)
		}
	}
	return name, nil
}

// splitUnescaped splits s on unescaped occurrences of sep, treating a backslash
// as escaping the following byte.
func splitUnescaped(s string, sep byte) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			i++
			cur.WriteByte(s[i])
		case s[i] == sep:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	parts = append(parts, cur.String())
	return parts
}

// unescape resolves backslash escapes: `\x` becomes the literal byte x.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
