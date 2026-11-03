package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// regionConfig puts each block on known lines: the upstream module call on
// lines 1-4 (ctf.coverage.module_source) and the unbounded aws requirement on
// lines 8-11 (ctf.origin.provider_unpinned).
const regionConfig = `module "logs" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.0"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
`

// A pre_plan finding anchored to an HCL block carries the block's first and
// last line as its SARIF region, and text output prints path:line.
func TestScanFindingsCarryTheBlockRegion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(regionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	res := runScanIn(t, dir, "scan", "--stage", "pre_plan", ".", "--format", "sarif", "--fail-on", "never")
	if res.code != 0 {
		t.Fatalf("scan exit = %d, stderr %q", res.code, res.stderr)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation *struct {
						Region *struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}

	want := map[string][2]int{
		"ctf.coverage.module_source":   {1, 4},
		"ctf.origin.provider_unpinned": {8, 11},
	}
	seen := map[string]bool{}
	for _, r := range doc.Runs[0].Results {
		lines, ok := want[r.RuleID]
		if !ok {
			continue
		}
		seen[r.RuleID] = true
		p := r.Locations[0].PhysicalLocation
		if p == nil || p.Region == nil {
			t.Errorf("%s has no region", r.RuleID)
			continue
		}
		if got := [2]int{p.Region.StartLine, p.Region.EndLine}; got != lines {
			t.Errorf("%s region = %v, want %v", r.RuleID, got, lines)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("no %s finding; the config no longer exercises it", id)
		}
	}

	text := runScanIn(t, dir, "scan", "--stage", "pre_plan", ".", "--format", "text", "--fail-on", "never")
	if !strings.Contains(text.stdout, "main.tf:1") || !strings.Contains(text.stdout, "main.tf:8") {
		t.Errorf("text output lacks path:line:\n%s", text.stdout)
	}
}
