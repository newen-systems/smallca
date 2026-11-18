package smallca

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/reference/cli.md from the help text")

// TestReferenceDocs keeps docs/reference/cli.md identical to the --help output,
// so the reference cannot drift from the code. Regenerate with:
//
//	go test ./internal/smallca -run TestReferenceDocs -update
func TestReferenceDocs(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("# smallca command reference\n\n")
	b.WriteString("Generated from `smallca --help` by `go test ./internal/smallca -run TestReferenceDocs -update`. Do not edit by hand.\n\n")
	b.WriteString("## smallca\n\n```text\n")
	writeMainHelp(&b)
	b.WriteString("```\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "\n## smallca %s\n\n```text\n", c.name)
		writeHelp(&b, c)
		b.WriteString("```\n")
	}
	path := filepath.Join("..", "..", "docs", "reference", "cli.md")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, b.Bytes()) {
		t.Fatalf("%s is stale or missing (%v); run: go test ./internal/smallca -run TestReferenceDocs -update", path, err)
	}
}
