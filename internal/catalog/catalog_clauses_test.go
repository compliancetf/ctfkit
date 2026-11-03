package catalog_test

import (
	"slices"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// shippedControl is the part of a catalog-1 controls[] entry these tests read.
// It decodes the embedded bytes directly rather than going through the
// ControlCatalog interface, because the interface has no way to list every
// control and these are assertions about the whole shipped document.
type shippedControl struct {
	ID                 string              `yaml:"id"`
	ClausesByFramework map[string][]string `yaml:"clausesByFramework"`
}

func shippedControls(t *testing.T) []shippedControl {
	t.Helper()
	var doc struct {
		Controls []shippedControl `yaml:"controls"`
	}
	if err := yaml.Unmarshal(catalog.EmbeddedBytes(), &doc); err != nil {
		t.Fatalf("the embedded catalog does not parse: %v", err)
	}
	if len(doc.Controls) == 0 {
		t.Fatal("the embedded catalog has no controls; this test is no longer checking anything")
	}
	return doc.Controls
}

// A framework with an empty clause list reaches a finding as a framework with
// nothing to cite: the disabled_control analyzer copies Frameworks and
// Framework straight into ctf.frameworks. The release catalog leaves such a
// framework out instead. It once carried 96 of these.
func TestNoEmptyClauseList(t *testing.T) {
	var empty []string
	for _, c := range shippedControls(t) {
		for fw, clauses := range c.ClausesByFramework {
			if len(clauses) == 0 {
				empty = append(empty, c.ID+" / "+fw)
			}
		}
	}
	if len(empty) > 0 {
		sort.Strings(empty)
		t.Errorf("%d clausesByFramework values are empty lists: %v", len(empty), empty)
	}
}

// Plan fixture 03 records a disabled_control finding on
// s3_bucket_versioning_enabled citing four SOC 2 clauses. Every clause the
// control catalog records for a framework has to reach the release catalog, so
// all four are asserted here, by clause identifier. The framework id is the
// catalog id, soc_2.
func TestFixture03ControlCarriesItsSOC2Clauses(t *testing.T) {
	const control = "s3_bucket_versioning_enabled"
	const framework = "soc_2"
	want := []string{"A1.2", "C1.2", "CC7.4", "PI1.5"}

	clauses := catalog.Embedded().Framework(ctfkit.ControlID(control), framework)
	have := make(map[string]bool, len(clauses))
	for _, id := range catalog.ClauseIdentifiers(clauses) {
		have[id] = true
	}

	for _, id := range want {
		if !have[id] {
			t.Errorf("%s / %s does not cite %s; it cites %v", control, framework, id, clauses)
		}
	}
}

// A clause title shortens to an identifier, never to a bare first word. The
// titles are spellings the embedded catalog carries.
func TestClauseIdentifier(t *testing.T) {
	tests := []struct {
		title string
		want  string
	}{
		{"CC7.2: The entity monitors system components", "CC7.2"},
		{"A1.2 The entity authorizes, designs, develops", "A1.2"},
		{"164.308(a)(1)(ii)(D): Information system activity review", "164.308(a)(1)(ii)(D)"},
		{"Denial Of Service Protection (SC-5)", "SC-5"},
		{"Account Management (AC-2)", "AC-2"},
		{"Article 25 Data protection by design and by default", "Article 25"},
		{"Requirement 10: Track and monitor all access to network resources", "Requirement 10"},
		{"Annex I (1.3)", "Annex I (1.3)"},
		{"Your Data-4", "Your Data-4"},
		{"Booting Up: Things to Do First-1", "Booting Up: Things to Do First-1"},
		{"Data protection", "Data protection"},
		{"Examine  firewall and router configurations", "Examine firewall and router configurations"},
		{"   ", ""},
	}
	for _, tt := range tests {
		if got := catalog.ClauseIdentifier(tt.title); got != tt.want {
			t.Errorf("ClauseIdentifier(%q) = %q, want %q", tt.title, got, tt.want)
		}
	}
}

// Two spellings of one clause collapse to one identifier, first seen first.
func TestClauseIdentifiersDeduplicates(t *testing.T) {
	got := catalog.ClauseIdentifiers([]string{"AC-2 Account Management", "Account Management (AC-2)", "", "Data protection"})
	if want := []string{"AC-2", "Data protection"}; !slices.Equal(got, want) {
		t.Errorf("ClauseIdentifiers() = %q, want %q", got, want)
	}
}
