package coverage

import (
	"encoding/json"
	"testing"

	"github.com/compliancetf/ctfkit/internal/inventory"
)

// TestFrameworkClausesSupportingTriState pins the SARIF side of the supporting
// tri-state: a framework the manifest did not classify carries no
// supportingClauses key at all, because [] would state "nothing hedged there",
// the claim the curation forbids for an unclassified mapping.
func TestFrameworkClausesSupportingTriState(t *testing.T) {
	clauses := map[string][]string{
		"soc_2":       {"CC7.3 The entity evaluates security events"},
		"pci_dss_v40": {"10.2 Audit logs are implemented"},
	}
	cases := []struct {
		name       string
		supporting map[string][]string
		// want maps a framework id to its marshaled supportingClauses, or ""
		// when the key must be absent.
		want map[string]string
	}{
		{
			name: "nil map: every framework unknown",
			want: map[string]string{"soc_2": "", "pci_dss_v40": ""},
		},
		{
			name:       "classified and nothing hedged",
			supporting: map[string][]string{"soc_2": {}, "pci_dss_v40": {}},
			want:       map[string]string{"soc_2": "[]", "pci_dss_v40": "[]"},
		},
		{
			name:       "a framework missing from the map stays unknown",
			supporting: map[string][]string{"soc_2": {"CC7.3 The entity evaluates security events"}},
			want:       map[string]string{"soc_2": `["CC7.3"]`, "pci_dss_v40": ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := frameworkClauses(inventory.Control{
				ClausesByFramework:           clauses,
				SupportingClausesByFramework: tc.supporting,
			})
			if len(got) != len(tc.want) {
				t.Fatalf("got %d frameworks, want %d", len(got), len(tc.want))
			}
			for _, entry := range got {
				raw, err := json.Marshal(entry)
				if err != nil {
					t.Fatalf("marshal %s: %v", entry.ID, err)
				}
				var fields map[string]json.RawMessage
				if unmarshalErr := json.Unmarshal(raw, &fields); unmarshalErr != nil {
					t.Fatalf("unmarshal %s: %v", entry.ID, unmarshalErr)
				}
				value, present := fields["supportingClauses"]
				want := tc.want[entry.ID]
				switch {
				case want == "" && present:
					t.Errorf("%s: supportingClauses = %s, want the key absent (unknown)", entry.ID, value)
				case want != "" && !present:
					t.Errorf("%s: supportingClauses absent, want %s", entry.ID, want)
				case want != "" && string(value) != want:
					t.Errorf("%s: supportingClauses = %s, want %s", entry.ID, value, want)
				}
			}
		})
	}
}
