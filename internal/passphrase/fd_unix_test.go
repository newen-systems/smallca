//go:build unix

package passphrase

import (
	"os"
	"syscall"
	"testing"
)

func TestFromFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("s3cret\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// Dup so FromFD, which closes its fd, is the only owner.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if got, err := FromFD(uintptr(fd)); err != nil || string(got) != "s3cret" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := FromFD(0); err == nil {
		t.Fatal("fd 0 accepted")
	}
}
