package catalog_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// manifestName is the file a served module carries at the root of its scope.
const manifestName = "compliancetf-manifest.json"

// fixtureRoot holds the recorded .terraform/modules trees the report and
// post_init cases are built against. They are the closest thing in the repo to
// what a customer actually downloads, and a re-record from the live registry
// refreshes them, so a catalog that lags the served manifests fails here.
const fixtureRoot = "../../testdata/fixtures"

// A finding whose control id the catalog cannot resolve is refused by
// ValidateFor, so any id a served manifest can name has to be in the embedded
// release catalog, whether it applied the control or listed it as not
// applicable. (delegation_unresolved tolerates an unknown id, but then the
// finding carries no control id.) The fixture manifests are the sample of real served
// manifests this repo has, so they are the sample this is asserted over.
//
// The embedded catalog once held 16 hand-written controls, and 10
// of the 12 ids the fixtures name resolved to nothing.
func TestEveryFixtureManifestControlIDResolves(t *testing.T) {
	ids := fixtureControlIDs(t)
	if len(ids) == 0 {
		t.Fatal("no control ids found under the fixture root; this test is no longer checking anything")
	}

	c := catalog.Embedded()
	var unresolved []string
	for _, id := range ids {
		ref, ok := c.Control(ctfkit.ControlID(id))
		if !ok {
			unresolved = append(unresolved, id)
			continue
		}
		if ref.Name == "" {
			t.Errorf("control %s resolves but carries no name", id)
		}
		if len(ref.ResourceTypes) == 0 {
			t.Errorf("control %s resolves but names no resource type", id)
		}
	}

	if len(unresolved) > 0 {
		t.Errorf("the embedded catalog cannot resolve %d of %d control ids a fixture manifest names: %v",
			len(unresolved), len(ids), unresolved)
	}
}

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
	Build struct {
		ControlsNotApplicable []string `json:"controls_not_applicable"`
	} `json:"build"`
}

func fixtureControlIDs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	forEachManifest(t, func(_ string, doc manifestDoc) {
		for _, c := range doc.Controls {
			if c.ControlID != "" {
				seen[c.ControlID] = true
			}
		}
		for _, id := range doc.Build.ControlsNotApplicable {
			seen[id] = true
		}
	})

	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
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
