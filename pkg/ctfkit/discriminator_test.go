package ctfkit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// discriminated is a valid ctf.policy.tagging finding carrying d.
func discriminated(t *testing.T, d string) ctfkit.Finding {
	t.Helper()
	f, err := ctfkit.NewFinding("ctf.policy.tagging", ctfkit.LevelError, ctfkit.KindFail,
		ctfkit.Message{Text: "Missing required tags"}, nil, validProperties())
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.Discriminator = d
	return f
}

// The discriminator feeds the SARIF fingerprint only; it is never part of a
// finding's JSON, so no projection can carry it.
func TestDiscriminatorIsNeverEncoded(t *testing.T) {
	const marker = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
	raw, err := json.Marshal(discriminated(t, marker))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), marker) || strings.Contains(strings.ToLower(string(raw)), "discriminator") {
		t.Errorf("the encoded finding carries the discriminator:\n%s", raw)
	}
}

// ValidateFor strips URL userinfo from the discriminator as it does from the
// message, so a module source with a token neither leaks it into the
// fingerprint input nor changes the fingerprint when the token rotates.
func TestValidateForStripsUserinfoFromTheDiscriminator(t *testing.T) {
	const id = "ctf.policy.tagging"
	cat := catalogWith("s3_bucket_versioning_enabled")

	var got []string
	for _, token := range []string{"oldtoken", "newtoken"} {
		f, err := discriminated(t, "git::https://x-access-token:"+token+"@github.com/bobthecorp/mod.git").
			ValidateFor(id, ctfkit.PostPlan, cat)
		if err != nil {
			t.Fatalf("ValidateFor: %v", err)
		}
		got = append(got, f.Discriminator)
	}

	const want = "git::https://github.com/bobthecorp/mod.git"
	for _, d := range got {
		if d != want {
			t.Errorf("Discriminator = %q, want %q", d, want)
		}
	}
}
