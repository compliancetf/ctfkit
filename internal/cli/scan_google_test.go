package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanGoogleFirewallsPass records that a google plan whose only changes
// are firewalls exits 0 at the default threshold: a deny-all-from-anywhere
// rule and a disabled rule are hardening, not exposure, and the google proof
// pack has no firewall rule that could tell them from an open allow rule.
func TestScanGoogleFirewallsPass(t *testing.T) {
	dir := t.TempDir()
	firewall := func(name, after string) string {
		return `{"address": "google_compute_firewall.` + name + `", "mode": "managed", "type": "google_compute_firewall",
			"name": "` + name + `", "provider_name": "registry.terraform.io/hashicorp/google",
			"change": {"actions": ["create"], "before": null, "after": ` + after + `, "after_unknown": {}}}`
	}
	plan := `{"format_version": "1.2", "terraform_version": "1.9.0", "resource_changes": [` +
		firewall("deny_all", `{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "deny": [{"protocol": "all"}], "allow": [], "disabled": false}`) + `,` +
		firewall("disabled", `{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp"}], "disabled": true}`) + `,` +
		firewall("allow_ssh", `{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}], "disabled": false}`) +
		`]}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"scan", "plan.json", "--chdir", dir, "--format", "json", "--fail-on", "error"}, scanRunContext...)
	if res := runScanIn(t, dir, args...); res.code != 0 {
		t.Errorf("exit %d, want 0\nstdout: %s\nstderr: %s", res.code, res.stdout, res.stderr)
	}
}
