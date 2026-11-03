package instancekey

import (
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestProviderGoldens: the terraform provider computes the same keys from
// apply PlannedState and tests them against its copy of these goldens
// (internal/verdict/testdata/instancekey). This checks that the golden data
// files of that copy are byte for byte the frozen set TestGoldens passes, so
// both sides answer to one oracle. It needs a provider checkout:
//
//	CTFKIT_PROVIDER_DIR=/path/to/terraform-provider-aws go test ./pkg/verdict/instancekey/ -run Provider
func TestProviderGoldens(t *testing.T) {
	root := os.Getenv("CTFKIT_PROVIDER_DIR")
	if root == "" {
		t.Skip("CTFKIT_PROVIDER_DIR not set: no provider checkout to cross-check")
	}
	theirs := filepath.Join(root, "internal", "verdict", "testdata", "instancekey")
	// Only the data files: the provider's FORMAT.md is edited for its public
	// tree, and it omits ref.py and the plan JSON parsing cases
	// (_edge_dupkey, _edge_surrogate), which test the ctfkit plan reader.
	// The type dirs are the ones TestGoldenSides holds to its list.
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "aws_*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("ctfkit goldens: %d type dirs, %v", len(dirs), err)
	}
	want := map[string]bool{}
	for _, dir := range append(dirs, "_edge") {
		dir = filepath.Base(dir)
		for _, f := range []string{"plan.json", "schema.json", "expected.json", "canonical.json"} {
			want[filepath.Join(dir, f)] = true
		}
	}
	for _, rel := range slices.Sorted(maps.Keys(want)) {
		ours, oerr := os.ReadFile(filepath.Join(goldenDir, rel))
		if oerr != nil {
			t.Fatal(oerr)
		}
		got, gerr := os.ReadFile(filepath.Join(theirs, rel))
		if gerr != nil || !bytes.Equal(got, ours) {
			t.Errorf("provider %s differs from the ctfkit golden (%v)", rel, gerr)
		}
	}
	// Nothing else may sit in the provider copy, so a stale or extra file
	// (a type ctfkit dropped, a new type not in goldenSides) fails too.
	err = filepath.WalkDir(theirs, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(theirs, path)
		if err != nil {
			return err
		}
		if !want[rel] && rel != "FORMAT.md" {
			t.Errorf("provider %s has no ctfkit golden data file", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
