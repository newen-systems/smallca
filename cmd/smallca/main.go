// Command smallca is a non-interactive, idempotent certificate authority for
// automation. See docs/reference/cli.md.
package main

import (
	"os"

	"github.com/newen-systems/smallca/internal/smallca"
)

func main() {
	os.Exit(smallca.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
