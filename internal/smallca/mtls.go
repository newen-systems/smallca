package smallca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Check is one named result of an mTLS check.
type Check struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// MTLSResult is the JSON output of mtls verify.
type MTLSResult struct {
	Valid  bool    `json:"valid"`
	Checks []Check `json:"checks"`
}

func (r *MTLSResult) add(name string, err error, okDetail string) {
	c := Check{Check: name, OK: err == nil, Detail: okDetail}
	if err != nil {
		c.Detail = err.Error()
	}
	r.Checks = append(r.Checks, c)
}

func (r *MTLSResult) finish() *MTLSResult {
	r.Valid = true
	for _, c := range r.Checks {
		r.Valid = r.Valid && c.OK
	}
	return r
}

// MTLSFiles is one side of an mTLS pair: its certificate (with any
// intermediates after it), optionally its key, and the CA bundle it uses to
// trust the other side.
type MTLSFiles struct {
	Certs []*x509.Certificate
	Key   string
	Trust []*x509.Certificate
}

// trustedFor checks peer's leaf chains to trust for the given usage, at the
// package clock, using the peer's own extra certificates as intermediates.
func trustedFor(peer []*x509.Certificate, trust []*x509.Certificate, usage x509.ExtKeyUsage, host string) (string, error) {
	if len(trust) == 0 {
		return "", errors.New("no CA certificates to trust it with")
	}
	rp, ip := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range trust {
		rp.AddCert(c)
	}
	for _, c := range peer[1:] {
		ip.AddCert(c)
	}
	chains, err := peer[0].Verify(x509.VerifyOptions{
		Roots: rp, Intermediates: ip, DNSName: host, CurrentTime: now(),
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		return "", err
	}
	path := ""
	for i, c := range chains[0] {
		if i > 0 {
			path += " -> "
		}
		path += c.Subject.String()
	}
	return path, nil
}

// MTLSOffline checks, without a network, that a server and a client
// certificate trust each other the way a TLS stack will check them: the
// client's CA bundle accepts the server certificate for serverAuth (and for
// host, if given), the server's CA bundle accepts the client certificate for
// clientAuth, and each key, when given, matches its certificate.
func MTLSOffline(server, client MTLSFiles, host string) *MTLSResult {
	r := &MTLSResult{}
	path, err := trustedFor(server.Certs, client.Trust, x509.ExtKeyUsageServerAuth, host)
	r.add("client trusts server certificate", err, path)
	path, err = trustedFor(client.Certs, server.Trust, x509.ExtKeyUsageClientAuth, "")
	r.add("server trusts client certificate", err, path)
	for _, side := range []struct {
		name  string
		files MTLSFiles
	}{{"server", server}, {"client", client}} {
		if side.files.Key == "" {
			continue
		}
		k, err := readKey(side.files.Key, nil)
		if err == nil && !keyMatches(k, side.files.Certs[0]) {
			err = errors.New("key does not match the certificate")
		}
		r.add(side.name+" key matches its certificate", err, "")
	}
	return r.finish()
}

// MTLSLive connects to target as an mTLS client: it presents the client
// certificate, checks the server certificate against the client's CA bundle,
// and reports whether the server accepted the client certificate.
func MTLSLive(ctx context.Context, target, serverName string, client MTLSFiles) *MTLSResult {
	r := &MTLSResult{}
	host, serverName := dialTarget(target, serverName)
	k, err := readKey(client.Key, nil)
	if err != nil {
		r.add("load client key", err, "")
		return r.finish()
	}
	chain := make([][]byte, len(client.Certs))
	for i, c := range client.Certs {
		chain[i] = c.Raw
	}
	pool := x509.NewCertPool()
	for _, c := range client.Trust {
		pool.AddCert(c)
	}
	cfg := &tls.Config{
		ServerName:   serverName,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: k, Leaf: client.Certs[0]}},
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			r.add("client trusts server certificate", err, "")
		} else {
			r.add("TLS handshake", err, "")
		}
		return r.finish()
	}
	defer conn.Close()
	tc := conn.(*tls.Conn)
	r.add("client trusts server certificate", nil, tc.ConnectionState().PeerCertificates[0].Subject.String())
	// With TLS 1.3 a server rejects a client certificate after the handshake,
	// so wait briefly for an alert. A timeout means the server kept the
	// connection open: it accepted the certificate.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	switch {
	case err == nil, errors.As(err, &ne) && ne.Timeout():
		r.add("server accepts client certificate", nil, "")
	case errors.Is(err, io.EOF):
		r.add("server accepts client certificate", errors.New("server closed the connection after the handshake; it probably rejected the client certificate"), "")
	default:
		r.add("server accepts client certificate", fmt.Errorf("server rejected it: %w", err), "")
	}
	return r.finish()
}
