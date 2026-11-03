package catalog_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// recordedRemediation is a ctf.coverage.module_source result from a plan
// fixture: the raw resource it points at and the module it recommends.
type recordedRemediation struct {
	fixture      string
	resourceType string
	moduleSource string
	version      string
	controlIDs   []string
}

// The plan fixtures record, for a raw resource, the compliance.tf module the
// module_source analyzer recommends and the version constraint it pins. That
// recommendation is ModuleFor answering from the release catalog, so the
// release catalog has to carry the module and the constraint the fixtures
// record. This reads them from the fixtures rather than restating them, so a
// re-recorded fixture and a stale catalog cannot pass together.
//
// Only results about a raw resource are read. A result about a module call -
// fixture 05's upstream iam-policy migration candidate - comes from the module
// source string, not from a ModuleFor lookup.
func TestReleaseCatalogCarriesTheRecordedRemediations(t *testing.T) {
	recorded := recordedRemediations(t, "01-raw-s3-no-ctf", "05-mixed-origin")
	if len(recorded) == 0 {
		t.Fatal("no module_source results about a raw resource in the fixtures; this test is no longer checking anything")
	}

	c := catalog.Embedded()
	host := c.Hosts()[c.DefaultHost()]

	for _, r := range recorded {
		t.Run(r.fixture+"/"+r.resourceType, func(t *testing.T) {
			mod, ok := c.ModuleFor(r.resourceType)
			if !ok {
				t.Fatalf("ModuleFor(%s) found no module; the fixture recommends %s", r.resourceType, r.moduleSource)
			}
			if got := strings.Replace(mod.Source, "{host}", host, 1); got != r.moduleSource {
				t.Errorf("ModuleFor(%s).Source resolves to %s, the fixture records %s", r.resourceType, got, r.moduleSource)
			}
			if mod.Version != r.version {
				t.Errorf("ModuleFor(%s).Version = %q, the fixture records %q", r.resourceType, mod.Version, r.version)
			}
			for _, id := range r.controlIDs {
				if _, ok := c.Control(ctfkit.ControlID(id)); !ok {
					t.Errorf("the fixture cites %s, which the release catalog cannot resolve", id)
				}
			}
		})
	}
}

func recordedRemediations(t *testing.T, fixtures ...string) []recordedRemediation {
	t.Helper()
	var out []recordedRemediation
	for _, name := range fixtures {
		path := filepath.Join("..", "..", "testdata", "fixtures", "plan", name, "expected", "findings.sarif")
		b, err := os.ReadFile(path) //nolint:gosec // a fixed path under the repo's own fixture root
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					RuleID     string `json:"ruleId"`
					Properties struct {
						ControlIDs  []string `json:"ctf.controlIds"`
						Remediation *struct {
							ModuleSource string `json:"moduleSource"`
							Version      string `json:"version"`
						} `json:"ctf.remediation"`
					} `json:"properties"`
					Locations []struct {
						LogicalLocations []struct {
							Kind               string `json:"kind"`
							FullyQualifiedName string `json:"fullyQualifiedName"`
						} `json:"logicalLocations"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, run := range doc.Runs {
			for _, res := range run.Results {
				if res.RuleID != "ctf.coverage.module_source" || res.Properties.Remediation == nil {
					continue
				}
				for _, loc := range res.Locations {
					for _, ll := range loc.LogicalLocations {
						if ll.Kind != ctfkit.LogicalLocationResource {
							continue
						}
						resourceType, _, _ := strings.Cut(ll.FullyQualifiedName, ".")
						out = append(out, recordedRemediation{
							fixture:      name,
							resourceType: resourceType,
							moduleSource: res.Properties.Remediation.ModuleSource,
							version:      res.Properties.Remediation.Version,
							controlIDs:   res.Properties.ControlIDs,
						})
					}
				}
			}
		}
	}
	return out
}
