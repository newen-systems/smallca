package dn

import "testing"

func TestParseDN(t *testing.T) {
	n, err := ParseDN("CN=Certificate Authority,O=EXAMPLE.TEST")
	if err != nil || n.CommonName != "Certificate Authority" || n.Organization[0] != "EXAMPLE.TEST" {
		t.Fatalf("n=%+v err=%v", n, err)
	}
	if _, err := ParseDN("CN=x,UNSUPPORTED=y"); err == nil {
		t.Fatal("unsupported attribute accepted")
	}
}

func TestParseDNAllAttributes(t *testing.T) {
	n, err := ParseDN("CN=name,O=org,OU=unit,C=AU,ST=state,L=locality")
	if err != nil {
		t.Fatal(err)
	}
	if n.CommonName != "name" || n.Organization[0] != "org" || n.OrganizationalUnit[0] != "unit" ||
		n.Country[0] != "AU" || n.Province[0] != "state" || n.Locality[0] != "locality" {
		t.Fatalf("n=%+v", n)
	}
}

func TestParseDNEscapedComma(t *testing.T) {
	// A backslash-escaped comma is a literal comma inside the value, not an RDN
	// separator, so this parses as a single CN.
	n, err := ParseDN(`CN=a\,b`)
	if err != nil {
		t.Fatal(err)
	}
	if n.CommonName != "a,b" {
		t.Fatalf("CommonName=%q, want %q", n.CommonName, "a,b")
	}
}

func TestParseDNEmptyValueRejected(t *testing.T) {
	if _, err := ParseDN("CN="); err == nil {
		t.Fatal("empty value accepted")
	}
}

func TestParseDNCaseInsensitiveType(t *testing.T) {
	n, err := ParseDN("cn=x,o=y")
	if err != nil || n.CommonName != "x" || n.Organization[0] != "y" {
		t.Fatalf("n=%+v err=%v", n, err)
	}
}
