package parser

import (
	"reflect"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

func TestIsOverrideFile(t *testing.T) {
	for name, want := range map[string]bool{
		"override.tf":             true,
		"override.tf.json":        true,
		"override.tofu":           true,
		"override.tofu.json":      true,
		"bucket_override.tf":      true,
		"modules/x/a_override.tf": true,
		"s3_override.tofu.json":   true,
		"main.tf":                 false,
		"override_x.tf":           false,
		"xoverride.tf":            false,
		"my-override.tf":          false,
		"override.json":           false,
		"override":                false,
		"README.md":               false,
	} {
		if got := IsOverrideFile(name); got != want {
			t.Errorf("IsOverrideFile(%q) = %v, want %v", name, got, want)
		}
	}
}

// PrimaryFiles drops override files and a .tf copy whose .tofu twin sits in
// the same directory; a twin is matched on the whole name and suffix family.
func TestPrimaryFiles(t *testing.T) {
	var files []ctfkit.ConfigFile
	for _, p := range []string{
		"main.tf", "main.tofu", // twin: main.tf goes
		"vars.tf.json", "vars.tofu.json", // twin: vars.tf.json goes
		"outputs.tf", "outputs.tofu.json", // different family: both stay
		"network.tf.json", "network.tofu", // different family: both stay
		"override.tf", "bucket_override.tofu", // overrides go
		"only.tf",                         // no twin
		"modules/a/main.tf", "main2.tofu", // twin in another directory does not count
		"modules/b/x.tf", "modules/b/x.tofu", // twin in a subdirectory
	} {
		files = append(files, ctfkit.ConfigFile{Path: p})
	}
	var got []string
	for _, f := range PrimaryFiles(files) {
		got = append(got, f.Path)
	}
	want := []string{
		"main.tofu", "vars.tofu.json", "outputs.tf", "outputs.tofu.json", "network.tf.json", "network.tofu",
		"only.tf", "modules/a/main.tf", "main2.tofu", "modules/b/x.tofu",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PrimaryFiles = %q\n            want %q", got, want)
	}
}
