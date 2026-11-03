package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The black-box tests exec a built binary. When TestMain reused ./ctfkit at the
// repository root whenever one existed, an old build - from a previous branch,
// or from before a subcommand was added - answered for the current source, and
// the suite reported failures such as "unknown command report" that no code in
// the tree produced. The binary under test has to be built from this tree on
// every run, somewhere nothing else writes.
func TestBinaryUnderTestIsNotTheRepositoryRootBuild(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}

	if filepath.Dir(binaryPath) == root {
		t.Fatalf("binaryPath = %s, the build at the repository root; a stale build there would answer for this tree", binaryPath)
	}
	if strings.HasPrefix(binaryPath, root+string(filepath.Separator)) {
		t.Errorf("binaryPath = %s is inside the repository, where another build can overwrite it", binaryPath)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Errorf("binaryPath %s does not exist: %v", binaryPath, err)
	}
}
