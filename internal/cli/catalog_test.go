package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/catalog"
)

// catalogServer serves body for every catalog path and records the request.
func catalogServer(t *testing.T, status int, sha string, body []byte) (*httptest.Server, *http.Request) {
	t.Helper()
	got := &http.Request{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = *r.Clone(r.Context())
		if sha != "" {
			w.Header().Set("X-Catalog-Sha256", sha)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func runCatalogPull(t *testing.T, srv *httptest.Server, args ...string) (string, error) {
	t.Helper()
	c := New("test")
	c.catalogTransport = srv.Client().Transport
	out := new(bytes.Buffer)
	c.rootCmd.SetOut(out)
	c.rootCmd.SetErr(new(bytes.Buffer))
	host := strings.TrimPrefix(srv.URL, "https://")
	c.rootCmd.SetArgs(append([]string{"catalog", "pull", "--host", host}, args...))
	err := c.Execute()
	return out.String(), err
}

func TestCatalogPull(t *testing.T) {
	body := catalog.EmbeddedBytes()
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	wantVersion := catalog.Embedded().Version().Version

	tests := []struct {
		name     string
		status   int
		sha      string
		body     []byte
		args     []string
		wantFile bool
		wantErr  string
		wantPath string
	}{
		{name: "latest is verified and written", status: 200, sha: good, body: body, wantFile: true, wantPath: "/v1/catalog/latest.yaml"},
		{name: "a version is fetched by name", status: 200, sha: good, body: body, args: []string{"--version", "2026.1109.0"}, wantFile: true, wantPath: "/v1/catalog/2026.1109.0.yaml"},
		{name: "a hash mismatch writes nothing", status: 200, sha: strings.Repeat("0", 64), body: body, wantErr: "X-Catalog-Sha256"},
		{name: "a missing hash writes nothing", status: 200, body: body, wantErr: "X-Catalog-Sha256"},
		{name: "a refusal passes the server message on", status: 403, body: []byte(`{"error": "The full control catalog needs a paid plan."}`), wantErr: "answered 403: The full control catalog needs a paid plan."},
		{name: "an invalid catalog writes nothing", status: 200, sha: hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("schema: x\n")); return s[:] }()), body: []byte("schema: x\n"), wantErr: "downloaded catalog"},
		{name: "a malformed version is refused before any request", status: 200, sha: good, body: body, args: []string{"--version", "2026.0105.0"}, wantErr: "not a catalog version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, req := catalogServer(t, tt.status, tt.sha, tt.body)
			t.Setenv(tokenEnvName(strings.TrimPrefix(srv.URL, "https://")), "bobthecorp-token")
			dest := filepath.Join(t.TempDir(), "nested", "catalog.yaml")

			out, err := runCatalogPull(t, srv, append(tt.args, "--out", dest)...)

			_, statErr := os.Stat(dest)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || ExitCode(err) != ExitEnvironment {
					t.Fatalf("err = %v (exit %d), want exit 2 containing %q", err, ExitCode(err), tt.wantErr)
				}
				if statErr == nil {
					t.Error("a file was written although the pull failed")
				}
				return
			}
			if err != nil {
				t.Fatalf("pull: %v", err)
			}
			if !tt.wantFile || statErr != nil {
				t.Fatalf("no file at %s: %v", dest, statErr)
			}
			if !strings.Contains(out, "catalog "+wantVersion+" written to "+dest) {
				t.Errorf("stdout = %q", out)
			}
			if req.URL.Path != tt.wantPath || req.Header.Get("Authorization") != "Bearer bobthecorp-token" {
				t.Errorf("request %s with Authorization %q", req.URL.Path, req.Header.Get("Authorization"))
			}
		})
	}
}

// Without the environment variable, the token comes from the credentials file
// terraform login writes, keyed by host.
func TestRegistryTokenReadsTheCredentialsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(tokenEnvName("registry.example.test"), "")
	dir := filepath.Join(home, ".terraform.d")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	creds := `{"credentials": {"registry.example.test": {"token": "from-file"}}}`
	if err := os.WriteFile(filepath.Join(dir, "credentials.tfrc.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := registryToken("registry.example.test"); err != nil || got != "from-file" {
		t.Errorf("registryToken = %q, %v; want the file token", got, err)
	}
	if _, err := registryToken("other.example.test"); err == nil || !strings.Contains(err.Error(), "TF_TOKEN_other_example_test") {
		t.Errorf("err = %v, want it to name the variable to set", err)
	}
}

func TestTokenEnvName(t *testing.T) {
	for host, want := range map[string]string{
		"registry.compliance.tf":     "TF_TOKEN_registry_compliance_tf",
		"registry.dev.compliance.tf": "TF_TOKEN_registry_dev_compliance_tf",
		"my-registry.example.test":   "TF_TOKEN_my__registry_example_test",
	} {
		if got := tokenEnvName(host); got != want {
			t.Errorf("tokenEnvName(%s) = %s, want %s", host, got, want)
		}
	}
}
