package cli

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// ctfkit report counts a root's own resources whatever syntax declares them,
// so a JSON root is no longer read as declaring none.
func TestReportCountsRootResourcesInEverySuffix(t *testing.T) {
	for _, suffix := range []string{"tf", "tofu", "tf-json", "tofu-json"} {
		t.Run(suffix, func(t *testing.T) {
			root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "postplan_json", suffix))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			runReport(t, append([]string{"--path", root, "--format", "receipt", "--out-dir", dir}, fixtureContext...)...)

			var receipt struct {
				Statement struct {
					RootResources struct {
						Declared int    `json:"declared"`
						Coverage string `json:"coverage"`
					} `json:"rootResources"`
				} `json:"statement"`
			}
			if err := json.Unmarshal(readFile(t, filepath.Join(dir, "receipt.json")), &receipt); err != nil {
				t.Fatalf("decode receipt: %v", err)
			}
			if got := receipt.Statement.RootResources; got.Declared != 2 || got.Coverage != "unattested" {
				t.Errorf("rootResources = %+v, want 2 declared, unattested", got)
			}
		})
	}
}
