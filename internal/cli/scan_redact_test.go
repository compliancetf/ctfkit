package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redactConfig declares one module block per scan finding path that quotes a
// module source, each source carrying CANARY- values in userinfo, a query or
// both: upstream (module_source error) and unbounded registry
// (floating_ref_unbounded), third party (module_source note), unknown registry
// host (module_source_unknown_registry), git with no ref and git on a branch
// (floating_ref).
const redactConfig = `module "upstream" {
  source = "terraform-aws-modules/vpc/aws?CANARY-query=1"
}

module "third" {
  source  = "bobthecorp/app/aws?CANARY-query=2"
  version = "1.0.0"
}

module "unknown" {
  source  = "CANARY-user:CANARY-token@registry.bobthecorp.example/net/vpc/aws?sshkey=CANARY-key"
  version = "1.0.0"
}

module "git" {
  source = "git::https://CANARY-user:CANARY-token@example.com/bobthecorp/app.git?sshkey=CANARY-key"
}

module "branch" {
  source = "git::https://CANARY-user:CANARY-token@example.com/bobthecorp/app.git?ref=main&sshkey=CANARY-key"
}
`

// TestScanRedactsEveryQuotedSource runs scan over redactConfig and requires
// every rule above to fire and no CANARY- value, query or userinfo to reach
// the SARIF.
func TestScanRedactsEveryQuotedSource(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(redactConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runScanIn(t, dir, "scan", "--stage", "pre_plan", "--format", "sarif", "--fail-on", "never", "--catalog", "embedded", ".")
	if got.code != ExitOK {
		t.Fatalf("exit = %d (%v)", got.code, got.err)
	}
	for _, rule := range []string{
		"ctf.coverage.module_source", "ctf.coverage.module_source_unknown_registry",
		"ctf.policy.floating_ref", "ctf.policy.floating_ref_unbounded",
	} {
		if !strings.Contains(got.stdout, `"ruleId": "`+rule+`"`) {
			t.Errorf("%s did not fire, so its redaction is not exercised:\n%s", rule, got.stdout)
		}
	}
	for _, leak := range []string{"CANARY-", "sshkey", "?ref", "@registry", "@example.com"} {
		if strings.Contains(got.stdout, leak) {
			t.Errorf("the SARIF carries %q:\n%s", leak, got.stdout)
		}
	}
}
