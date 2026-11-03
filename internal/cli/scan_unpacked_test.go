package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unpackedNote starts the stderr line a scan prints for providers no rule
// pack describes.
const unpackedNote = "ctfkit: no rule pack for "

// fallbackNote ends the stderr line a scan prints when the lock file pins a
// provider major that has no pack.
const fallbackNote = "has no rule pack; checked with "

// planOf writes a plan with one created resource per provider address, and
// the lock file when one is given, to a new directory.
func planOf(t *testing.T, lock string, resources map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var changes []string
	for address, provider := range resources {
		changes = append(changes, `{"address": "`+address+`", "mode": "managed", "type": "`+
			strings.Split(address, ".")[0]+`", "name": "x", "provider_name": "`+provider+
			`", "change": {"actions": ["create"], "before": null, "after": {}, "after_unknown": {}}}`)
	}
	plan := `{"format_version": "1.2", "terraform_version": "1.9.0", "resource_changes": [` + strings.Join(changes, ",") + `]}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	if lock != "" {
		if err := os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestScanNotesUnpackedProviders records the stderr notes about rule packs:
// one line for providers no pack describes, none for providers that manage no
// infrastructure, and one for a locked major that has no pack. Neither note
// reaches stdout.
func TestScanNotesUnpackedProviders(t *testing.T) {
	const aws5 = `provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.100.0"
  constraints = "~> 5.0"
  hashes      = ["h1:bobthecorp"]
}
`
	tests := []struct {
		name, input, wantUnpacked, wantFallback string
	}{
		{"packed providers only", fixtureInput(t, "11-sensitive-public-exposure"), "", ""},
		{"providers that manage no infrastructure", fixtureInput(t, "09-unknown-provider"), "", ""},
		{"terraform_data and an unpacked cloud", planOf(t, "", map[string]string{
			"terraform_data.marker":        "terraform.io/builtin/terraform",
			"azurerm_storage_account.logs": "registry.terraform.io/hashicorp/azurerm",
		}), "registry.terraform.io/hashicorp/azurerm", ""},
		{"locked major with no pack", planOf(t, aws5, map[string]string{
			"aws_s3_bucket.logs": "registry.terraform.io/hashicorp/aws",
		}), "", "hashicorp/aws 5.x has no rule pack; checked with aws/v6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"scan", "plan.json", "--chdir", tt.input, "--format", "json", "--fail-on", "never"}, scanRunContext...)
			res := runScanIn(t, tt.input, args...)
			if res.code != 0 {
				t.Fatalf("exit %d, want 0\n%s", res.code, res.stderr)
			}
			var unpacked, fallback []string
			for _, line := range strings.Split(res.stderr, "\n") {
				switch {
				case strings.HasPrefix(line, unpackedNote):
					unpacked = append(unpacked, line)
				case strings.Contains(line, fallbackNote):
					fallback = append(fallback, line)
				}
			}
			check := func(kind string, lines []string, want string) {
				switch {
				case want == "" && len(lines) != 0:
					t.Errorf("stderr has %s notes %q, want none", kind, lines)
				case want != "" && (len(lines) != 1 || !strings.Contains(lines[0], want)):
					t.Errorf("stderr has %s notes %q, want one line naming %s", kind, lines, want)
				}
			}
			check("unpacked-provider", unpacked, tt.wantUnpacked)
			check("fallback", fallback, tt.wantFallback)
			if strings.Contains(res.stdout, unpackedNote) || strings.Contains(res.stdout, fallbackNote) {
				t.Error("a note reached stdout")
			}
		})
	}
}
