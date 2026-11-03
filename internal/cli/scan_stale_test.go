package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
)

// staleCatalog writes the release catalog under a version older than the one
// embedded in the binary, which is the whole of what makes a catalog stale.
func staleCatalog(t *testing.T) string {
	t.Helper()
	versionLine := regexp.MustCompile(`(?m)^version: "[^"]*"$`)
	body := versionLine.ReplaceAll(catalog.EmbeddedBytes(), []byte(`version: "2026.1.0"`))
	if string(body) == string(catalog.EmbeddedBytes()) {
		t.Fatal("the embedded catalog has no top-level version line to rewrite")
	}
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

type runNotice struct {
	Descriptor struct {
		ID string `json:"id"`
	} `json:"descriptor"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
}

func stdoutNotices(t *testing.T, stdout string) []runNotice {
	t.Helper()
	var doc struct {
		Runs []struct {
			Invocations []struct {
				Notifications []runNotice `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not SARIF: %v\n%s", err, stdout)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("want one run, got %d", len(doc.Runs))
	}
	var out []runNotice
	for _, inv := range doc.Runs[0].Invocations {
		out = append(out, inv.Notifications...)
	}
	return out
}

// Per the scan specification, a catalog older than the embedded release is a run-level
// ctf.catalog.stale notification at level note, in SARIF as well as on stderr.
// It is never a finding and never changes the exit code.
func TestScanStaleCatalogIsASARIFNotification(t *testing.T) {
	dir := fixtureInput(t, "01-raw-s3-no-ctf")
	args := append([]string{"scan", "plan.json", "--format", "sarif", "--catalog", staleCatalog(t)}, scanRunContext...)

	got := runScanIn(t, dir, args...)
	if got.code == 2 {
		t.Fatalf("scan exited 2: %v\n%s", got.err, got.stderr)
	}
	if !strings.Contains(got.stderr, "ctf.catalog.stale") {
		t.Errorf("stderr does not carry the stale notice:\n%s", got.stderr)
	}

	notices := stdoutNotices(t, got.stdout)
	if len(notices) != 1 {
		t.Fatalf("want one run-level notification, got %d", len(notices))
	}
	n := notices[0]
	if n.Descriptor.ID != "ctf.catalog.stale" || n.Level != "note" {
		t.Errorf("notification = %s at %s, want ctf.catalog.stale at note", n.Descriptor.ID, n.Level)
	}
	if !strings.Contains(n.Message.Text, "2026.1.0") || strings.HasPrefix(n.Message.Text, "ctf.catalog.stale") {
		t.Errorf("message = %q, want the catalog versions without the id prefix the id field already carries", n.Message.Text)
	}
}

// The control: the embedded catalog is never stale, so the run carries no
// notification and no invocations key.
func TestScanEmbeddedCatalogCarriesNoNotification(t *testing.T) {
	dir := fixtureInput(t, "01-raw-s3-no-ctf")
	args := append([]string{"scan", "plan.json", "--format", "sarif", "--catalog", "embedded"}, scanRunContext...)

	got := runScanIn(t, dir, args...)
	if got.code == 2 {
		t.Fatalf("scan exited 2: %v\n%s", got.err, got.stderr)
	}
	if strings.Contains(got.stdout, `"invocations"`) {
		t.Errorf("a run on the embedded catalog wrote an invocations key")
	}
}
