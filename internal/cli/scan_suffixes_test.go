package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// A directory whose only configuration is JSON is read by the origin rules
// through the loader and the command, not only in the analyzer.
func TestScanOriginRulesReadJSONConfiguration(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "origin", "suffixes", "tf-json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	res := runScanIn(t, dir, "scan", "--stage", "pre_plan", ".", "--format", "json", "--fail-on", "never")
	if res.code != 0 {
		t.Fatalf("scan exit = %d, stderr %q", res.code, res.stderr)
	}
	var doc struct {
		Findings []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"findings"`
	}
	if err = json.Unmarshal([]byte(res.stdout), &doc); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	got := []string{}
	for _, f := range doc.Findings {
		got = append(got, f.RuleID+"|"+f.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	sort.Strings(got)
	want := []string{
		// The upstream vpc module, now that JSON blocks are read.
		"ctf.coverage.module_source|main.tf.json",
		"ctf.origin.provider_unpinned|main.tf.json",
		"ctf.origin.provider_unverified|main.tf.json",
		"ctf.policy.floating_ref_unbounded|main.tf.json",
		"ctf.policy.floating_ref|main.tf.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
