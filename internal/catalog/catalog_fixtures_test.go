package catalog_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
)

// manifestName is the file a served module carries at the root of its scope.
const manifestName = "compliancetf-manifest.json"

// fixtureRoot holds the recorded .terraform/modules trees the report command
// is built against. They are the closest thing in the repo to what a customer
// actually downloads.
const fixtureRoot = "../../testdata/fixtures/report"

// Every framework a fixture manifest cites must have a remediation host, or a
// finding carrying it names a framework no endpoint exists for.
func TestEveryFixtureManifestFrameworkHasAHost(t *testing.T) {
	hosts := catalog.Embedded().Hosts()

	var missing []string
	forEachManifest(t, func(path string, doc manifestDoc) {
		for _, fw := range doc.Module.Frameworks {
			if _, ok := hosts[fw]; !ok {
				missing = append(missing, fw)
			}
		}
		for _, c := range doc.Controls {
			for fw := range c.ClausesByFramework {
				if _, ok := hosts[fw]; !ok {
					missing = append(missing, fw)
				}
			}
		}
	})

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("the embedded catalog hosts no endpoint for: %v", missing)
	}
}

type manifestDoc struct {
	Module struct {
		Frameworks []string `json:"frameworks"`
	} `json:"module"`
	Controls []struct {
		ControlID          string              `json:"control_id"`
		ClausesByFramework map[string][]string `json:"clauses_by_framework"`
	} `json:"controls"`
}

// forEachManifest walks the fixture tree by hand rather than with a glob,
// because the manifests live under .terraform/modules and most glob helpers
// skip a dotted path segment.
func forEachManifest(t *testing.T, fn func(path string, doc manifestDoc)) {
	t.Helper()
	err := filepath.WalkDir(fixtureRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != manifestName {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // a path under the repo's own fixture root
		if err != nil {
			return err
		}
		var doc manifestDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Errorf("%s does not parse: %v", path, err)
			return nil
		}
		fn(path, doc)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", fixtureRoot, err)
	}
}
