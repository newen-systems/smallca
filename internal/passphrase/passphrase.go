// Package passphrase reads a key password from a non-interactive source: a
// file, an inherited file descriptor or standard input. It never prompts.
package passphrase

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxBytes caps the accepted password length.
const MaxBytes = 4096

// Clear overwrites b so the password does not linger on the heap longer than
// needed. Best effort only: the Go runtime may still hold earlier copies.
func Clear(b []byte) { clear(b) }

// FromFile reads the password from the named file.
func FromFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the password file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// FromFD reads the password from an inherited file descriptor and closes it.
// fd 0 is refused: use the stdin source for that.
func FromFD(fd uintptr) ([]byte, error) {
	if fd == 0 {
		return nil, errors.New("password fd must not be 0, use --password-stdin")
	}
	f := os.NewFile(fd, "password-fd")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not open", fd)
	}
	defer f.Close()
	return Read(f)
}

// Read reads a password from r. At most MaxBytes are accepted, trailing
// newlines (LF or CRLF) are trimmed and an empty result is an error.
func Read(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		Clear(b)
		return nil, fmt.Errorf("password exceeds %d bytes", MaxBytes)
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		return nil, errors.New("empty password")
	}
	return b, nil
}
