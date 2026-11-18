//go:build unix

package smallca

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInitPassphraseFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(w, testPass)
	w.Close()
	// smallca closes the fd it is given, so give it a duplicate: two os.Files
	// on one fd number would close it twice, possibly after reuse.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	dir := filepath.Join(t.TempDir(), "ca")
	m := mustRun(t, "", "root", "create", "--root-dir", dir, "--subject", "CN=FD Root", "--crv", "P-256", "--password-fd", fmt.Sprint(fd))
	if m["changed"] != true {
		t.Fatal("fd create did not create the root")
	}
}
