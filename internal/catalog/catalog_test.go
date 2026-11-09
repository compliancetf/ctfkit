package catalog_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The embedded release catalog is the catalog every run gets when the operator
// names no file, so its content is part of the contract and is asserted here
// rather than in a fixture.
func TestEmbeddedAnswersEveryInterfaceMethod(t *testing.T) {
	c := catalog.Embedded()

	if got := c.Version(); got.Version != "2026.11.1" || got.Provenance != "embedded" {
		t.Errorf("Version() = %+v, want version 2026.11.1 from embedded", got)
	}

	// The embedded catalog holds the CIS v6.0 controls only. A control sits on
	// the resource type that carries the setting: MFA delete is set on the
	// versioning sub-resource, SSL enforcement on the bucket.
	if ids := c.ControlsFor("aws_s3_bucket"); !contains(ids, "s3_bucket_enforces_ssl") {
		t.Errorf("ControlsFor(aws_s3_bucket) = %v, want it to contain s3_bucket_enforces_ssl", ids)
	}
	if got := c.ControlsFor("aws_s3_bucket_versioning"); !contains(got, "s3_bucket_mfa_delete_enabled") {
		t.Errorf("ControlsFor(aws_s3_bucket_versioning) = %v, want it to contain s3_bucket_mfa_delete_enabled", got)
	}
	if got := c.ControlsFor("aws_s3_bucket_object"); len(got) != 0 {
		t.Errorf("ControlsFor(aws_s3_bucket_object) = %v, want empty for a type the catalog does not cover", got)
	}

	ref, ok := c.Control("s3_bucket_mfa_delete_enabled")
	if !ok {
		t.Fatal("Control(s3_bucket_mfa_delete_enabled) not found")
	}
	if ref.Name == "" || !reflect.DeepEqual(ref.ResourceTypes, []string{"aws_s3_bucket_versioning"}) {
		t.Errorf("Control(s3_bucket_mfa_delete_enabled) = %+v, want the bucket-versioning entry", ref)
	}
	if _, found := c.Control("no_such_control"); found {
		t.Error("Control(no_such_control) reported found")
	}
	// A control outside CIS v6.0 is not in the embedded catalog.
	if _, found := c.Control("s3_bucket_logging_enabled"); found {
		t.Error("Control(s3_bucket_logging_enabled) found, want only CIS v6.0 controls embedded")
	}

	if got := c.Frameworks("s3_bucket_mfa_delete_enabled"); !reflect.DeepEqual(got, []string{"cis_v600"}) {
		t.Errorf("Frameworks(s3_bucket_mfa_delete_enabled) = %v, want [cis_v600]", got)
	}
	if got := c.Frameworks("no_such_control"); len(got) != 0 {
		t.Errorf("Frameworks(no_such_control) = %v, want empty", got)
	}

	if got := c.Framework("s3_bucket_mfa_delete_enabled", "cis_v600"); len(got) == 0 {
		t.Error("Framework(s3_bucket_mfa_delete_enabled, cis_v600) returned no clause")
	}
	if got := c.Framework("s3_bucket_mfa_delete_enabled", "soc_2"); len(got) != 0 {
		t.Errorf("Framework(s3_bucket_mfa_delete_enabled, soc_2) = %v, want empty: only CIS v6.0 clauses are embedded", got)
	}
	if got := c.Framework("no_such_control", "cis_v600"); len(got) != 0 {
		t.Errorf("Framework(no_such_control, cis_v600) = %v, want empty", got)
	}

	mod, ok := c.ModuleFor("aws_s3_bucket")
	if !ok {
		t.Fatal("ModuleFor(aws_s3_bucket) not found")
	}
	if mod.Source != "{host}.compliance.tf/terraform-aws-modules/s3-bucket/aws" {
		t.Errorf("ModuleFor(aws_s3_bucket).Source = %q, want the unsubstituted template", mod.Source)
	}
	if mod.Version != "~> 5.0" {
		t.Errorf("ModuleFor(aws_s3_bucket).Version = %q, want ~> 5.0", mod.Version)
	}
	if !contains(mod.Controls, "s3_bucket_restrict_public_write_access") {
		t.Errorf("ModuleFor(aws_s3_bucket).Controls = %v, want it to enforce s3_bucket_restrict_public_write_access", mod.Controls)
	}
	if _, ok := c.ModuleFor("aws_lambda_function"); ok {
		t.Error("ModuleFor(aws_lambda_function) reported a module")
	}

	if got := c.Modules(); len(got) != 2 {
		t.Errorf("Modules() returned %d entries, want 2: s3-bucket and sqs", len(got))
	}

	// The sqs module covers aws_sqs_queue and enforces the controls the
	// control catalog places on that type, derived rather than listed.
	sqs, found := c.ModuleFor("aws_sqs_queue")
	if !found {
		t.Fatal("ModuleFor(aws_sqs_queue) not found")
	}
	if sqs.Source != "{host}.compliance.tf/terraform-aws-modules/sqs/aws" || sqs.Version != "~> 4.0" {
		t.Errorf("ModuleFor(aws_sqs_queue) = %s %s, want the sqs module at ~> 4.0", sqs.Source, sqs.Version)
	}
	for _, id := range c.ControlsFor("aws_sqs_queue") {
		if !contains(sqs.Controls, id) {
			t.Errorf("control %s sits on aws_sqs_queue but the sqs module does not enforce it", id)
		}
	}

	// A host label is not a framework id, which is the whole reason this map
	// exists: pci_dss_v40 is served from pcidss.compliance.tf.
	hosts := c.Hosts()
	if hosts["pci_dss_v40"] != "pcidss" {
		t.Errorf("Hosts()[pci_dss_v40] = %q, want pcidss", hosts["pci_dss_v40"])
	}
	if c.DefaultHost() != "soc_2" {
		t.Errorf("DefaultHost() = %q, want soc_2", c.DefaultHost())
	}
	if got := hosts[c.DefaultHost()]; got != "soc2" {
		t.Errorf("the default host label is %q, want soc2", got)
	}

	// Every framework a control maps to must be hostable, which is what lets a
	// finding name a remediation host for it.
	for _, id := range c.ControlsFor("aws_db_instance") {
		for _, fw := range c.Frameworks(id) {
			if _, ok := hosts[fw]; !ok {
				t.Errorf("control %s maps to framework %s, which is not a key of Hosts()", id, fw)
			}
		}
	}
}

// A caller that mutates what it was handed must not reach back into the
// catalog: the catalog is an immutable snapshot shared by every analyzer.
func TestReturnedValuesAreCopies(t *testing.T) {
	c := catalog.Embedded()

	ids := c.ControlsFor("aws_s3_bucket")
	ids[0] = "clobbered"
	if got := c.ControlsFor("aws_s3_bucket"); got[0] == "clobbered" {
		t.Error("ControlsFor shares its slice with the catalog")
	}

	ref, _ := c.Control("s3_bucket_mfa_delete_enabled")
	ref.ResourceTypes[0] = "clobbered"
	ref.ClausesByFramework["cis_v600"][0] = "clobbered"
	again, _ := c.Control("s3_bucket_mfa_delete_enabled")
	if again.ResourceTypes[0] == "clobbered" || again.ClausesByFramework["cis_v600"][0] == "clobbered" {
		t.Error("Control shares its slices with the catalog")
	}

	fws := c.Frameworks("s3_bucket_mfa_delete_enabled")
	fws[0] = "clobbered"
	if c.Frameworks("s3_bucket_mfa_delete_enabled")[0] == "clobbered" {
		t.Error("Frameworks shares its slice with the catalog")
	}

	clauses := c.Framework("s3_bucket_mfa_delete_enabled", "cis_v600")
	clauses[0] = "clobbered"
	if c.Framework("s3_bucket_mfa_delete_enabled", "cis_v600")[0] == "clobbered" {
		t.Error("Framework shares its slice with the catalog")
	}

	mod, _ := c.ModuleFor("aws_s3_bucket")
	mod.Controls[0] = "clobbered"
	mod.ResourceTypes[0] = "clobbered"
	again2, _ := c.ModuleFor("aws_s3_bucket")
	if again2.Controls[0] == "clobbered" || again2.ResourceTypes[0] == "clobbered" {
		t.Error("ModuleFor shares its slices with the catalog")
	}

	mods := c.Modules()
	mods[0].Controls[0] = "clobbered"
	if c.Modules()[0].Controls[0] == "clobbered" {
		t.Error("Modules shares its slices with the catalog")
	}

	hosts := c.Hosts()
	hosts["cis_v600"] = "clobbered"
	if c.Hosts()["cis_v600"] == "clobbered" {
		t.Error("Hosts shares its map with the catalog")
	}
}

func TestLoadReadsAFile(t *testing.T) {
	c, err := catalog.Load(filepath.Join("testdata", "small.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := c.Framework("s3_bucket_versioning_enabled", "soc_2"), []string{"CC6.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Framework(s3_bucket_versioning_enabled, soc_2) = %v, want %v", got, want)
	}
	if got := c.Version(); got.Version != "2026.9.0" || got.Provenance != "file" {
		t.Errorf("Version() = %+v, want 2026.9.0 from file", got)
	}
}

func TestLoadRejects(t *testing.T) {
	small, err := os.ReadFile(filepath.Join("testdata", "small.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown major",
			body: strings.Replace(string(small), "ctf.catalog/1", "ctf.catalog/2", 1),
			want: "2",
		},
		{
			name: "foreign schema",
			body: strings.Replace(string(small), "ctf.catalog/1", "ctf.exceptions/1", 1),
			want: "ctf.exceptions/1",
		},
		{
			name: "not yaml",
			body: "schema: [ctf.catalog/1\n",
			want: "does not parse",
		},
		{
			name: "invalid version",
			body: strings.Replace(string(small), `version: "2026.9.0"`, `version: "2026.09"`, 1),
			want: "2026.09",
		},
		{
			// A missing key parses to the zero value, so without a presence
			// check a catalog with no controls at all would load and quietly
			// find nothing.
			name: "missing controls",
			body: string(small[:strings.Index(string(small), "controls:")]) + string(small[strings.Index(string(small), "modules:"):]),
			want: "controls",
		},
		{
			name: "missing defaultHost",
			body: strings.Replace(string(small), "defaultHost: soc_2\n", "", 1),
			want: "defaultHost",
		},
		{
			name: "duplicate control id",
			body: strings.Replace(string(small), "modules:", `  - id: s3_bucket_versioning_enabled
    name: Versioning Enabled again
    resourceTypes: [aws_s3_bucket]
    clausesByFramework:
      soc_2: [CC6.1]
modules:`, 1),
			want: "only once",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "catalog.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := catalog.Load(path)
			if err == nil {
				t.Fatal("Load accepted the file")
			}
			if !errors.Is(err, catalog.ErrCatalog) {
				t.Errorf("error %v does not wrap ErrCatalog", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not name %q", err, tc.want)
			}
		})
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	_, err := catalog.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("Load accepted a missing file")
	}
	if !errors.Is(err, catalog.ErrCatalog) {
		t.Errorf("error %v does not wrap ErrCatalog", err)
	}
}

// The lookup order is --catalog FILE, else the home file, else the embedded
// release catalog. A catalog is never discovered from the repository under
// analysis, so nothing here reads the working directory.
func TestResolveLookupOrder(t *testing.T) {
	small := filepath.Join("testdata", "small.yaml")
	body, err := os.ReadFile(small)
	if err != nil {
		t.Fatal(err)
	}

	homeWith := func(t *testing.T, write bool) {
		t.Helper()
		home := t.TempDir()
		if write {
			dir := filepath.Join(home, ".ctf")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "control-requirements.yaml"), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("HOME", home)
	}

	t.Run("home file when the flag is empty", func(t *testing.T) {
		homeWith(t, true)
		c, v, err := catalog.Resolve("")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v.Provenance != "home" {
			t.Errorf("provenance = %q, want home", v.Provenance)
		}
		if c.Version() != v {
			t.Errorf("Version() = %+v, want the returned %+v", c.Version(), v)
		}
	})

	t.Run("embedded when no home file", func(t *testing.T) {
		homeWith(t, false)
		_, v, err := catalog.Resolve("")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v.Provenance != "embedded" {
			t.Errorf("provenance = %q, want embedded", v.Provenance)
		}
	})

	t.Run("embedded pins past a home file", func(t *testing.T) {
		homeWith(t, true)
		_, v, err := catalog.Resolve("embedded")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v.Provenance != "embedded" {
			t.Errorf("provenance = %q, want embedded", v.Provenance)
		}
	})

	t.Run("flag file wins over a home file", func(t *testing.T) {
		homeWith(t, true)
		_, v, err := catalog.Resolve(small)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if v.Provenance != "file" {
			t.Errorf("provenance = %q, want file", v.Provenance)
		}
	})

	t.Run("a named file that is missing is an error", func(t *testing.T) {
		homeWith(t, true)
		if _, _, err := catalog.Resolve(filepath.Join(t.TempDir(), "absent.yaml")); !errors.Is(err, catalog.ErrCatalog) {
			t.Errorf("error %v does not wrap ErrCatalog", err)
		}
	})

	t.Run("an invalid home file is an error, not a silent fallback", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, ".ctf")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "control-requirements.yaml"), []byte("schema: ctf.catalog/9\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", home)
		if _, _, err := catalog.Resolve(""); !errors.Is(err, catalog.ErrCatalog) {
			t.Errorf("error %v does not wrap ErrCatalog", err)
		}
	})
}

// Check is what schemacheck runs over a catalog fixture, so the rules live in
// one place and the embedded catalog is held to them too.
func TestCheckReportsEveryBrokenRule(t *testing.T) {
	broken := `
schema: ctf.catalog/1
version: "1.0.0"
hosts:
  soc_2: soc2
defaultHost: hipaa
controls:
  - id: dup
    name: Duplicated
    resourceTypes: [aws_s3_bucket]
    clausesByFramework:
      pci_dss_v40: ["3.4.1"]
  - id: dup
    name: Duplicated again
    resourceTypes: [aws_s3_bucket, aws_s3_bucket]
    clausesByFramework: {}
modules:
  - resourceTypes: [aws_s3_bucket]
    source: "{host}.compliance.tf/{host}/s3-bucket/aws"
    version: "~> 4.6"
    controls: [dup, absent]
  - resourceTypes: [aws_s3_bucket]
    source: "other.compliance.tf/terraform-aws-modules/s3-bucket/aws"
    version: "~> 4.6"
    controls: []
`
	msgs := catalog.Check([]byte(broken))
	for _, want := range []string{
		"only once",
		"at most one modules[] entry",
		"only once in a controls[] entry",
		"must be defined in controls[]",
		"defaultHost",
		"clausesByFramework",
		"at most once",
	} {
		if !strings.Contains(strings.Join(msgs, "\n"), want) {
			t.Errorf("Check did not report %q; got %v", want, msgs)
		}
	}
}

func TestCheckPassesTheEmbeddedCatalog(t *testing.T) {
	if msgs := catalog.Check(catalog.EmbeddedBytes()); len(msgs) != 0 {
		t.Errorf("the embedded catalog breaks its own rules: %v", msgs)
	}
}

// Both the value and the pointer satisfy the sealed interface, so a caller may
// hold either.
var (
	_ ctfkit.ControlCatalog = catalog.FileCatalog{}
	_ ctfkit.ControlCatalog = &catalog.FileCatalog{}
)

func contains[T comparable](haystack []T, needle T) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// The CIS-subset hint belongs only to the embedded catalog's content: a copy
// of it read as a file gets the hint, and a catalog of any other version,
// such as the full one, does not, since telling its user to pass --catalog
// would be wrong.
func TestEmbeddedSubsetNoteFollowsTheEmbeddedVersion(t *testing.T) {
	embedded := catalog.Embedded().Version().Version
	for _, tc := range []struct {
		name     string
		version  ctfkit.CatalogVersion
		wantNote bool
	}{
		{"embedded", ctfkit.CatalogVersion{Version: embedded, Provenance: "embedded"}, true},
		{"a file copy of it", ctfkit.CatalogVersion{Version: embedded, Provenance: "file"}, true},
		{"another catalog", ctfkit.CatalogVersion{Version: "2099.1.0", Provenance: "home"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := catalog.EmbeddedSubsetNote(tc.version)
			if got := strings.Contains(note, "CIS v6.0"); got != tc.wantNote {
				t.Errorf("EmbeddedSubsetNote(%+v) = %q, want a CIS note: %v", tc.version, note, tc.wantNote)
			}
		})
	}
}
