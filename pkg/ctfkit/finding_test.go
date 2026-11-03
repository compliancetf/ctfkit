package ctfkit_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// NewFinding is the only supported way to build a Finding.
var _ = ctfkit.NewFinding

// validProperties returns a property bag with every required field set.
func validProperties() ctfkit.Properties {
	return ctfkit.Properties{
		Schema:     "1.0",
		Stage:      ctfkit.PostPlan,
		ControlIDs: []ctfkit.ControlID{"s3_bucket_versioning_enabled"},
		Frameworks: []ctfkit.FrameworkClauses{{ID: "soc_2", Clauses: []string{"CC6.1"}}},
		Preventive: true,
	}
}

func ExampleNewFinding() {
	f, err := ctfkit.NewFinding(
		"ctf.coverage.module_source",
		ctfkit.LevelError,
		ctfkit.KindFail,
		ctfkit.Message{Text: "Raw aws_s3_bucket where a compliance.tf module exists"},
		[]ctfkit.Location{{
			PhysicalLocation: &ctfkit.PhysicalLocation{
				ArtifactLocation: ctfkit.ArtifactLocation{URI: "modules/data/main.tf"},
				Region:           &ctfkit.Region{StartLine: 42},
			},
		}},
		validProperties(),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(f.RuleID, f.Level, f.Props.Stage)
	// Output: ctf.coverage.module_source error post_plan
}

// The marshaled form is the contract every renderer and every adapter reads,
// so it is pinned exactly.
func TestFindingMarshalsToTheResultObject(t *testing.T) {
	p := ctfkit.Properties{
		Schema:      "1.0",
		Stage:       ctfkit.PostPlan,
		Preventive:  true,
		Remediation: &ctfkit.Remediation{ModuleSource: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws", Version: "4.6.0"},
	}

	f, err := ctfkit.NewFinding("ctf.coverage.module_source", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Raw aws_s3_bucket"},
		[]ctfkit.Location{{PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "main.tf"},
			Region:           &ctfkit.Region{StartLine: 42},
		}}}, p)
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	got, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	const want = `{"ruleId":"ctf.coverage.module_source","level":"error","kind":"fail",` +
		`"message":{"text":"Raw aws_s3_bucket"},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":42}}}],` +
		`"properties":{"ctf.controlIds":[],"ctf.frameworks":[],` +
		`"ctf.preventive":true,` +
		`"ctf.remediation":{"moduleSource":"soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws","version":"4.6.0"},` +
		`"ctf.schema":"1.0","ctf.stage":"post_plan"}}`
	if string(got) != want {
		t.Errorf("marshaled finding is\n  %s\nwant\n  %s", got, want)
	}
}

// A coverage finding maps to no control, and the key is still present and
// empty rather than absent or null.
func TestMarshalAlwaysCarriesTheRequiredKeys(t *testing.T) {
	f, err := ctfkit.NewFinding("ctf.origin.provider", ctfkit.LevelWarning, ctfkit.KindFail,
		ctfkit.Message{Text: "Unapproved provider"}, nil,
		ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PrePlan})
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal returned %v", err)
	}

	for _, key := range []string{
		ctfkit.PropertySchema, ctfkit.PropertyStage, ctfkit.PropertyControlIDs,
		ctfkit.PropertyFrameworks, ctfkit.PropertyPreventive,
	} {
		if _, ok := doc.Properties[key]; !ok {
			t.Errorf("marshaled bag is missing required key %s", key)
		}
	}
	if got := string(doc.Properties[ctfkit.PropertyControlIDs]); got != "[]" {
		t.Errorf("%s marshaled as %s, want []", ctfkit.PropertyControlIDs, got)
	}
	for _, key := range []string{ctfkit.PropertyAttributes, ctfkit.PropertyRemediation, ctfkit.PropertyException} {
		if _, ok := doc.Properties[key]; ok {
			t.Errorf("unset optional key %s was marshaled anyway", key)
		}
	}
}

func TestNewFindingSortsEveryUnorderedList(t *testing.T) {
	p := ctfkit.Properties{
		Schema:     "1.0",
		Stage:      ctfkit.PostPlan,
		ControlIDs: []ctfkit.ControlID{"s3_bucket_versioning_enabled", "s3_bucket_encryption_enabled"},
		Frameworks: []ctfkit.FrameworkClauses{
			{ID: "soc_2", Clauses: []string{"CC7.2", "CC6.1"}},
			{ID: "pci_dss_v40", Clauses: []string{"3.4"}},
		},
		Attributes: []string{"versioning", "acl", "server_side_encryption_configuration"},
	}
	locs := []ctfkit.Location{
		{PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "main.tf"},
			Region:           &ctfkit.Region{StartLine: 90},
		}},
		{PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "main.tf"},
			Region:           &ctfkit.Region{StartLine: 12},
		}},
		{PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "buckets.tf"},
			Region:           &ctfkit.Region{StartLine: 7},
		}},
	}

	f, err := ctfkit.NewFinding("ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Missing required tags"}, locs, p)
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	wantControls := []ctfkit.ControlID{"s3_bucket_encryption_enabled", "s3_bucket_versioning_enabled"}
	if got := f.Props.ControlIDs; !equalControls(got, wantControls) {
		t.Errorf("ControlIDs = %v, want %v", got, wantControls)
	}
	if got := f.Props.Frameworks[0].ID; got != "pci_dss_v40" {
		t.Errorf("Frameworks are not sorted by id: first is %q", got)
	}
	if got := f.Props.Frameworks[1].Clauses; got[0] != "CC6.1" || got[1] != "CC7.2" {
		t.Errorf("clauses are not sorted: %v", got)
	}
	if got := f.Props.Attributes[0]; got != "acl" {
		t.Errorf("attributes are not sorted: first is %q", got)
	}

	wantOrder := []string{"buckets.tf:7", "main.tf:12", "main.tf:90"}
	for i, want := range wantOrder {
		got := fmt.Sprintf("%s:%d",
			f.Locations[i].PhysicalLocation.ArtifactLocation.URI,
			f.Locations[i].PhysicalLocation.Region.StartLine)
		if got != want {
			t.Errorf("location %d is %s, want %s", i, got, want)
		}
	}
}

func TestNewFindingStripsUserinfoFromEveryStringItStores(t *testing.T) {
	p := validProperties()
	p.Remediation = &ctfkit.Remediation{
		ModuleSource: "git::https://deploy:s3cr3t@git.example.com/modules/s3.git",
	}

	f, err := ctfkit.NewFinding("ctf.coverage.module_source", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Module source https://user:tok3n@example.com/m is not a compliance.tf endpoint"},
		[]ctfkit.Location{{
			PhysicalLocation: &ctfkit.PhysicalLocation{
				ArtifactLocation: ctfkit.ArtifactLocation{URI: "git::https://u:p@host/repo.git//modules/s3"},
			},
			LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: "module.s3[\"https://u:p@host/repo\"]", Kind: "module",
			}},
		}}, p)
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	stored := []string{
		f.Message.Text,
		f.Locations[0].PhysicalLocation.ArtifactLocation.URI,
		f.Locations[0].LogicalLocations[0].FullyQualifiedName,
		f.Props.Remediation.ModuleSource,
	}
	for _, s := range stored {
		for _, secret := range []string{"s3cr3t", "tok3n", "u:p@"} {
			if contains(s, secret) {
				t.Errorf("stored string %q still carries %q", s, secret)
			}
		}
	}
}

func TestStripUserinfo(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"no url here", "no url here"},
		{"https://user:pass@host/path", "https://host/path"},
		{"git::https://user:pass@host/repo.git", "git::https://host/repo.git"},
		{"hg::http://user:pass@host/repo", "hg::http://host/repo"},
		{"s3::https://key:secret@s3.eu-west-1.amazonaws.com/bucket/mod.zip",
			"s3::https://s3.eu-west-1.amazonaws.com/bucket/mod.zip"},
		{"git::ssh://git@host/org/repo.git", "git::ssh://host/org/repo.git"},
		// No scheme, so the user name is left alone: this is a module source,
		// not a credential.
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		// An at sign inside a path is not userinfo.
		{"https://host/path/a@b", "https://host/path/a@b"},
		{"see https://u:p@host/x and https://v:q@other/y",
			"see https://host/x and https://other/y"},
	}
	for _, tt := range tests {
		if got := ctfkit.StripUserinfo(tt.in); got != tt.want {
			t.Errorf("StripUserinfo(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// RedactSource drops the query and every userinfo form a module source can
// carry, and leaves a source with neither unchanged.
func TestRedactSource(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"registry address", "terraform-aws-modules/vpc/aws", "terraform-aws-modules/vpc/aws"},
		{"served with disable query", "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable=x",
			"soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"},
		{"local path", "../shared", "../shared"},
		{"git userinfo and query", "git::https://CANARY-u:CANARY-t@example.com/org/app.git?ref=v1&sshkey=CANARY-k",
			"git::https://example.com/org/app.git"},
		{"ssh user", "git::ssh://git@example.com/org/app.git//sub?ref=v1", "git::ssh://example.com/org/app.git//sub"},
		{"scp form", "git@github.com:org/app.git", "github.com:org/app.git"},
		{"getter then scp form", "git::CANARY-u@github.com:org/app.git", "git::github.com:org/app.git"},
		{"scheme-less userinfo", "CANARY-u:CANARY-t@registry.example.com/ns/name/aws", "registry.example.com/ns/name/aws"},
		// Anything it cannot read as an address prints the placeholder, never
		// its text: an at sign it could not place, whitespace, control
		// characters, invalid UTF-8.
		{"at sign in a path", "https://example.com/path/a@b.zip", ctfkit.UnparsedSource},
		{"userinfo after a path", "../CANARY-u:CANARY-t@gone?sshkey=CANARY-k", ctfkit.UnparsedSource},
		{"whitespace", "../CANARY dir", ctfkit.UnparsedSource},
		{"control character", "../CANARY\x1b[31m", ctfkit.UnparsedSource},
		{"invalid UTF-8", "../CANARY\xff", ctfkit.UnparsedSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ctfkit.RedactSource(tt.in); got != tt.want {
				t.Errorf("RedactSource(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// RedactPath redacts component by component: credentials and queries in a
// directory name go, the rest of the path stays.
func TestRedactPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{".terraform/modules/app/main.tf", ".terraform/modules/app/main.tf"},
		{"../CANARY-u:CANARY-t@shared?sshkey=CANARY-k/main.tf", "../shared/main.tf"},
		{"modules/CANARY-user:CANARY-token@shared?sshkey=CANARY-key/main.tf", "modules/shared/main.tf"},
		{"git::https://CANARY-u:CANARY-t@example.com/repo.git?ref=v1", "git::https://example.com/repo.git"},
		// Whitespace alone keeps the name.
		{"modules/my module/main.tf", "modules/my module/main.tf"},
		{"modules/my%20module/main.tf", "modules/my%20module/main.tf"},
		// Percent-encoded "@" and "?", in either case, and
		// a malformed escape fail closed, one component at a time.
		{"../CANARY-u:CANARY-t%40shared/main.tf", "../" + ctfkit.UnparsedSource + "/main.tf"},
		{"../CANARY-u%3aCANARY-t%40shared/main.tf", "../" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%3Fsshkey=CANARY-k/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%3fsshkey=CANARY-k/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%zz/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%2/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/tab%09dir/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/tab\tdir/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/nl%0Adir/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		// Encoded separators, and double encoding, decoded until stable.
		{"modules/a%2Fb/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/a%5Cb/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"../CANARY-u:CANARY-t%2540shared/main.tf", "../" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%253Fsshkey=CANARY-k/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%25252540x/main.tf", "modules/" + ctfkit.UnparsedSource + "/main.tf"},
		{"modules/shared%2Dv2/main.tf", "modules/shared%2Dv2/main.tf"},
	}
	for _, tt := range tests {
		if got := ctfkit.RedactPath(tt.in); got != tt.want {
			t.Errorf("RedactPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewFindingCopiesInputs(t *testing.T) {
	p := validProperties()
	p.Remediation = &ctfkit.Remediation{ModuleSource: "soc2.compliance.tf/m", Version: "1.0.0"}
	locs := []ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
		FullyQualifiedName: "aws_s3_bucket.logs", Kind: "resource",
	}}}}

	f, err := ctfkit.NewFinding("ctf.policy.tagging", ctfkit.LevelWarning, ctfkit.KindFail,
		ctfkit.Message{Text: "Missing required tag"}, locs, p)
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	p.ControlIDs[0] = "changed"
	p.Frameworks[0].Clauses[0] = "changed"
	p.Remediation.Version = "changed"
	locs[0].LogicalLocations[0].FullyQualifiedName = "aws_s3_bucket.changed"

	if got := f.Props.ControlIDs[0]; got != "s3_bucket_versioning_enabled" {
		t.Errorf("control id changed under the finding: %q", got)
	}
	if got := f.Props.Frameworks[0].Clauses[0]; got != "CC6.1" {
		t.Errorf("clause changed under the finding: %q", got)
	}
	if got := f.Props.Remediation.Version; got != "1.0.0" {
		t.Errorf("remediation changed under the finding: %q", got)
	}
	if got := f.Locations[0].LogicalLocations[0].FullyQualifiedName; got != "aws_s3_bucket.logs" {
		t.Errorf("location changed under the finding: %q", got)
	}
}

func TestNewFindingRejectsInvalidInput(t *testing.T) {
	noSchema := validProperties()
	noSchema.Schema = ""

	badStage := validProperties()
	badStage.Stage = "post_destroy"

	presetException := validProperties()
	presetException.Exception = &ctfkit.ExceptionProperty{Allowed: true}

	tests := []struct {
		name   string
		ruleID string
		level  string
		kind   string
		props  ctfkit.Properties
	}{
		{"empty rule id", "", ctfkit.LevelError, ctfkit.KindFail, validProperties()},
		{"rule id outside the format", "coverage.module_source", ctfkit.LevelError, ctfkit.KindFail, validProperties()},
		{"unknown level", "ctf.policy.tagging", "critical", ctfkit.KindFail, validProperties()},
		{"unknown kind", "ctf.policy.tagging", ctfkit.LevelError, "violation", validProperties()},
		{"no schema version", "ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail, noSchema},
		{"unknown stage", "ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail, badStage},
		{"analyzer set the exception property", "ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail, presetException},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ctfkit.NewFinding(tt.ruleID, tt.level, tt.kind,
				ctfkit.Message{Text: "irrelevant"}, nil, tt.props); err == nil {
				t.Error("NewFinding accepted the finding, want an error")
			}
		})
	}
}

func TestValidateAcceptsAFindingFromNewFinding(t *testing.T) {
	f, err := ctfkit.NewFinding("ctf.risk.sensitive_change", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Bucket becomes public"}, nil, validProperties())
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate rejected a finding NewFinding built: %v", err)
	}
}

func equalControls(a, b []ctfkit.ControlID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestWithExceptionIsTheOnlyWayTheExceptionIsSet(t *testing.T) {
	f, err := ctfkit.NewFinding("ctf.coverage.module_source", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Raw aws_s3_bucket"},
		[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
			FullyQualifiedName: "aws_s3_bucket.logs", Kind: ctfkit.LogicalLocationResource,
		}}}}, validProperties())
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}
	if f.Props.Exception != nil {
		t.Fatal("a finding from NewFinding already carries an exception")
	}

	suppressed := ctfkit.WithException(f, ctfkit.ExceptionProperty{Allowed: true, TTLSeconds: 15552000})

	if suppressed.Props.Exception == nil || !suppressed.Props.Exception.Allowed {
		t.Error("WithException did not record the waiver")
	}
	if f.Props.Exception != nil {
		t.Error("WithException changed the finding it was given instead of returning a copy")
	}
	if suppressed.Kind != ctfkit.KindFail || suppressed.Level != ctfkit.LevelError {
		t.Error("WithException changed the kind or level; a suppressed finding keeps both")
	}

	raw, err := json.Marshal(suppressed)
	if err != nil {
		t.Fatalf("Marshal returned %v", err)
	}
	if !contains(string(raw), `"ctf.exception":{"allowed":true,"ttlSeconds":15552000}`) {
		t.Errorf("marshaled finding does not carry the exception: %s", raw)
	}
}

func TestSubjectFallbackOrder(t *testing.T) {
	tests := []struct {
		name string
		locs []ctfkit.Location
		want string
	}{
		{"no locations", nil, ""},
		{
			"file location only",
			[]ctfkit.Location{{PhysicalLocation: &ctfkit.PhysicalLocation{
				ArtifactLocation: ctfkit.ArtifactLocation{URI: "main.tf"},
			}}},
			"",
		},
		{
			// A coverage finding names a module call and no resource, so the
			// module address is the fallback subject rather than nothing.
			"module address when there is no resource",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: "module.s3", Kind: ctfkit.LogicalLocationModule,
			}}}},
			"module.s3",
		},
		{
			// An origin.provider finding at post_plan names only a provider
			// instance. With no subject, a rule-level exception could never
			// target it. This case once asserted "".
			"provider address when there is no resource or module",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: "provider[\"registry.terraform.io/hashicorp/random\"]", Kind: ctfkit.LogicalLocationProvider,
			}}}},
			"provider[\"registry.terraform.io/hashicorp/random\"]",
		},
		{
			"a module address wins over a provider address",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{
				{FullyQualifiedName: "provider.aws", Kind: ctfkit.LogicalLocationProvider},
				{FullyQualifiedName: "module.s3", Kind: ctfkit.LogicalLocationModule},
			}}},
			"module.s3",
		},
		{
			"a resource address wins over a provider address",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{
				{FullyQualifiedName: "provider.aws", Kind: ctfkit.LogicalLocationProvider},
				{FullyQualifiedName: "aws_s3_bucket.logs", Kind: ctfkit.LogicalLocationResource},
			}}},
			"aws_s3_bucket.logs",
		},
		{
			// A kind the SDK has no constant for still names something, and
			// an empty subject makes it unreachable to an exception.
			"any other logical location is the last fallback",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{{
				FullyQualifiedName: "data.aws_caller_identity.current", Kind: "data",
			}}}},
			"data.aws_caller_identity.current",
		},
		{
			"a provider address wins over another kind",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{
				{FullyQualifiedName: "data.aws_caller_identity.current", Kind: "data"},
				{FullyQualifiedName: "provider.aws", Kind: ctfkit.LogicalLocationProvider},
			}}},
			"provider.aws",
		},
		{
			"a resource address wins over a module address",
			[]ctfkit.Location{{LogicalLocations: []ctfkit.LogicalLocation{
				{FullyQualifiedName: "module.s3", Kind: ctfkit.LogicalLocationModule},
				{FullyQualifiedName: "aws_s3_bucket.logs", Kind: ctfkit.LogicalLocationResource},
			}}},
			"aws_s3_bucket.logs",
		},
		{
			// NewFinding sorts locations, so the subject of a finding with
			// several is the first in that order, not in the caller's.
			"several resources resolve in sorted location order",
			[]ctfkit.Location{
				{PhysicalLocation: &ctfkit.PhysicalLocation{
					ArtifactLocation: ctfkit.ArtifactLocation{URI: "z.tf"},
				}, LogicalLocations: []ctfkit.LogicalLocation{
					{FullyQualifiedName: "aws_s3_bucket.z", Kind: ctfkit.LogicalLocationResource},
				}},
				{PhysicalLocation: &ctfkit.PhysicalLocation{
					ArtifactLocation: ctfkit.ArtifactLocation{URI: "a.tf"},
				}, LogicalLocations: []ctfkit.LogicalLocation{
					{FullyQualifiedName: "aws_s3_bucket.a", Kind: ctfkit.LogicalLocationResource},
				}},
			},
			"aws_s3_bucket.a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ctfkit.NewFinding("ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail,
				ctfkit.Message{Text: "Missing required tags"}, tt.locs, validProperties())
			if err != nil {
				t.Fatalf("NewFinding returned %v, want no error", err)
			}
			if got := f.Subject(); got != tt.want {
				t.Errorf("Subject() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateForChecksTheRunnerAgreements(t *testing.T) {
	const id = "ctf.policy.tagging"
	cat := catalogWith("s3_bucket_versioning_enabled")
	f, err := ctfkit.NewFinding(id, ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Missing required tags"}, nil, validProperties())
	if err != nil {
		t.Fatalf("NewFinding returned %v, want no error", err)
	}

	if _, err := f.ValidateFor(id, ctfkit.PostPlan, cat); err != nil {
		t.Errorf("ValidateFor rejected a matching finding: %v", err)
	}
	if _, err := f.ValidateFor("ctf.origin.provider", ctfkit.PostPlan, cat); err == nil {
		t.Error("ValidateFor accepted a finding emitted under another analyzer's id")
	}
	if _, err := f.ValidateFor(id, ctfkit.PrePlan, cat); err == nil {
		t.Error("ValidateFor accepted a finding claiming a stage that did not run")
	}
	if _, err := f.ValidateFor(id, ctfkit.PostPlan, nil); err == nil {
		t.Error("ValidateFor accepted a finding with no catalog to check its controls against")
	}
	if _, err := f.ValidateFor(id, ctfkit.PostPlan, catalogWith("s3_bucket_logging_enabled")); err == nil {
		t.Error("ValidateFor accepted a control id the catalog does not hold")
	}

	marked := ctfkit.WithException(f, ctfkit.ExceptionProperty{Allowed: true})
	if _, err := marked.ValidateFor(id, ctfkit.PostPlan, cat); err == nil {
		t.Error("ValidateFor accepted a finding that already carries an exception")
	}
}

// A Finding assembled by struct literal bypasses NewFinding, so the runner
// check is where a credential is taken out.
func TestValidateForReturnsASanitizedCopy(t *testing.T) {
	f := ctfkit.Finding{
		RuleID: "ctf.coverage.module_source",
		Level:  ctfkit.LevelError,
		Kind:   ctfkit.KindFail,
		Message: ctfkit.Message{
			Text: "Module source git::https://u:s3cr3t@host/repo.git is not served",
		},
		Locations: []ctfkit.Location{{PhysicalLocation: &ctfkit.PhysicalLocation{
			ArtifactLocation: ctfkit.ArtifactLocation{URI: "git::https://u:s3cr3t@host/repo.git"},
		}}},
		Props: ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PrePlan},
	}

	clean, err := f.ValidateFor("ctf.coverage.module_source", ctfkit.PrePlan, catalogWith())
	if err != nil {
		t.Fatalf("ValidateFor returned %v, want the sanitized copy", err)
	}
	for _, s := range []string{clean.Message.Text, clean.Locations[0].PhysicalLocation.ArtifactLocation.URI} {
		if contains(s, "s3cr3t") {
			t.Errorf("the returned copy still carries the credential: %q", s)
		}
	}
	if !contains(f.Message.Text, "s3cr3t") {
		t.Error("ValidateFor changed the finding it was given instead of returning a copy")
	}
}

func TestSortFindingsIsDeterministic(t *testing.T) {
	at := func(rule, uri string, line int, resource string) ctfkit.Finding {
		var locs []ctfkit.Location
		if uri != "" || resource != "" {
			l := ctfkit.Location{}
			if uri != "" {
				l.PhysicalLocation = &ctfkit.PhysicalLocation{
					ArtifactLocation: ctfkit.ArtifactLocation{URI: uri},
					Region:           &ctfkit.Region{StartLine: line},
				}
			}
			if resource != "" {
				l.LogicalLocations = []ctfkit.LogicalLocation{{
					FullyQualifiedName: resource, Kind: ctfkit.LogicalLocationResource,
				}}
			}
			locs = []ctfkit.Location{l}
		}
		f, err := ctfkit.NewFinding(rule, ctfkit.LevelError, ctfkit.KindFail,
			ctfkit.Message{Text: "finding"}, locs,
			ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan})
		if err != nil {
			t.Fatalf("NewFinding returned %v, want no error", err)
		}
		return f
	}

	fs := ctfkit.Findings{
		at("ctf.policy.tagging", "main.tf", 90, "aws_s3_bucket.z"),
		at("ctf.coverage.module_source", "main.tf", 12, "aws_s3_bucket.b"),
		at("ctf.policy.tagging", "buckets.tf", 3, "aws_s3_bucket.a"),
		at("ctf.coverage.module_source", "main.tf", 12, "aws_s3_bucket.a"),
	}
	ctfkit.SortFindings(fs)

	want := []string{
		"ctf.coverage.module_source aws_s3_bucket.a",
		"ctf.coverage.module_source aws_s3_bucket.b",
		"ctf.policy.tagging aws_s3_bucket.a",
		"ctf.policy.tagging aws_s3_bucket.z",
	}
	for i, w := range want {
		if got := fs[i].RuleID + " " + fs[i].Subject(); got != w {
			t.Errorf("position %d is %q, want %q", i, got, w)
		}
	}
}

// Two findings that agree on every sort key are still ordered, and suppressing
// one does not move it.
func TestSortFindingsBreaksTiesWithoutTheException(t *testing.T) {
	build := func(text string) ctfkit.Finding {
		f, err := ctfkit.NewFinding("ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail,
			ctfkit.Message{Text: text}, nil,
			ctfkit.Properties{Schema: "1.0", Stage: ctfkit.PostPlan})
		if err != nil {
			t.Fatalf("NewFinding returned %v, want no error", err)
		}
		return f
	}

	fs := ctfkit.Findings{build("missing Owner"), build("missing CostCenter")}
	ctfkit.SortFindings(fs)
	first := fs[0].Message.Text

	shuffled := ctfkit.Findings{fs[1], fs[0]}
	ctfkit.SortFindings(shuffled)
	if shuffled[0].Message.Text != first {
		t.Error("the tie-break is not stable across input orders")
	}

	suppressed := ctfkit.Findings{
		ctfkit.WithException(fs[0], ctfkit.ExceptionProperty{Allowed: true, EntryID: "exc-1"}),
		fs[1],
	}
	ctfkit.SortFindings(suppressed)
	if suppressed[0].Message.Text != first {
		t.Error("recording a waiver moved a finding in the sort order")
	}
}

func catalogWith(ids ...ctfkit.ControlID) ctfkit.ControlCatalog {
	controls := make(map[ctfkit.ControlID]ctfkit.ControlRef, len(ids))
	for _, id := range ids {
		controls[id] = ctfkit.ControlRef{ID: id}
	}
	return fakeCatalog{controls: controls}
}
