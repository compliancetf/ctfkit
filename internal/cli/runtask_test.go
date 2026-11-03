package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

const (
	runtaskKey      = "bobthecorp-run-task-hmac-key"
	runtaskPayload  = "../../adapters/hcp/testdata/post-plan.json"
	runtaskPlan     = "../../testdata/fixtures/plan/01-raw-s3-no-ctf/input/plan.json"
	runtaskPlanPath = "/api/v2/plans/plan-bobthecorp0001/json-output"
)

// lockedBuffer is stderr shared by the server goroutines and the test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// noVerdictRequired copies the valid inputs with the profile re-signed by
// the test profile key and verdict_required false.
func noVerdictRequired(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "inputs")
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(gateInputs, "valid"))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profile.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct{ Payload string }
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var prof map[string]any
	if err = json.Unmarshal(body, &prof); err != nil {
		t.Fatal(err)
	}
	prof["verdict_required"] = false
	if body, err = json.Marshal(prof); err != nil {
		t.Fatal(err)
	}
	// The key derives from a public label, as in pkg/verdict's generator.
	d := sha256.Sum256([]byte("compliancetf.test-profile-key-es256/bobthecorp"))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(verdict.PAE(verdict.PayloadProfile, body))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"payloadType": verdict.PayloadProfile,
		"payload":    base64.StdEncoding.EncodeToString(body),
		"signatures": []map[string]string{{"keyid": verdict.KeyID(der), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "profile.dsse.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runtaskArgs(inputs, keyFile, host, receipts string, extra ...string) []string {
	return append([]string{"runtask", "serve", "--hmac-key-file", keyFile,
		"--hostname", host, "--receipt-dir", receipts, "--org", "bobthecorp",
		"--profile", filepath.Join(inputs, "profile.dsse.json"), "--floor", filepath.Join(inputs, "floor.dsse.json"),
		"--bundle-dir", filepath.Join(inputs, "bundles")}, extra...)
}

func writeKeyFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hmac.key")
	if err := os.WriteFile(p, []byte(runtaskKey+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRuntaskServeRefuses(t *testing.T) {
	inputs := filepath.Join(gateInputs, "valid")
	key := writeKeyFile(t, 0o600)
	receipts := t.TempDir()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no key file", []string{"runtask", "serve", "--receipt-dir", receipts}, `missing required flags for "ctfkit runtask serve": --hmac-key-file, --org, --profile, --floor, --bundle-dir; see "ctfkit runtask serve --help"`},
		{"key file readable by others", runtaskArgs(inputs, writeKeyFile(t, 0o644), "app.terraform.io", receipts), "0600"},
		{"relative key file", runtaskArgs(inputs, "hmac.key", "app.terraform.io", receipts), "absolute path"},
		{"missing receipt dir", runtaskArgs(inputs, key, "app.terraform.io", filepath.Join(receipts, "absent")), "is not a directory; create it or name an existing one"},
		{"expired profile", runtaskArgs(filepath.Join(gateInputs, "expired-profile"), key, "app.terraform.io", receipts), "signed inputs refused"},
		{"plain HTTP off loopback", runtaskArgs(inputs, key, "app.terraform.io", receipts, "--listen", "0.0.0.0:0"), "needs --tls-cert"},
		{"half a TLS pair", runtaskArgs(inputs, key, "app.terraform.io", receipts, "--tls-cert", key), "go together"},
		{"hostname with a path", runtaskArgs(inputs, key, "app.terraform.io/x", receipts), "hostname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg := runGate(gateCLI(t, inputs), tt.args)
			if code != ExitEnvironment || !strings.Contains(msg, tt.want) {
				t.Fatalf("exit %d %q, want 2 with %q", code, msg, tt.want)
			}
		})
	}
}

// TestRuntaskServe drives the command end to end over loopback: the signed
// profile decides the receipt status, real analyzers produce the findings,
// and a signal ends the server with exit 0.
func TestRuntaskServe(t *testing.T) {
	tests := []struct {
		name       string
		inputs     func(t *testing.T) string
		wantStatus string
		wantTask   string
	}{
		{"verdict_required fails a mutating run closed", func(*testing.T) string { return filepath.Join(gateInputs, "valid") }, "failed", "failed"},
		{"no verdict_required is single-resource-only", noVerdictRequired, "single-resource-only", "passed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := tt.inputs(t)
			plan, err := os.ReadFile(runtaskPlan)
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan map[string]any, 1)
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == runtaskPlanPath:
					_, _ = w.Write(plan)
				case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/callback"):
					var m map[string]any
					_ = json.NewDecoder(r.Body).Decode(&m)
					results <- m
				default:
					http.NotFound(w, r)
				}
			}))
			defer api.Close()

			c := gateCLI(t, inputs)
			c.runtaskTransport = api.Client().Transport
			receipts := t.TempDir()
			stderr := &lockedBuffer{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.rootCmd.SetContext(ctx)
			c.rootCmd.SetArgs(runtaskArgs(inputs, writeKeyFile(t, 0o600), strings.TrimPrefix(api.URL, "https://"), receipts,
				"--listen", "127.0.0.1:0"))
			c.rootCmd.SetErr(stderr)
			done := make(chan error, 1)
			go func() { done <- c.Execute() }()

			addr := waitListening(t, stderr, done)
			raw, err := os.ReadFile(runtaskPayload)
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.ReplaceAll(raw, []byte("https://app.terraform.io"), []byte(api.URL))
			raw = bytes.Replace(raw, []byte("2026-10-27T12:00:00.000Z"), []byte("2026-10-19T11:59:00Z"), 1)
			raw = bytes.Replace(raw, []byte(`"mandatory"`), []byte(`"advisory"`), 1)
			mac := hmac.New(sha512.New, []byte(runtaskKey))
			_, _ = mac.Write(raw)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-TFC-Task-Signature", hex.EncodeToString(mac.Sum(nil)))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, stderr.String())
			}
			var res map[string]any
			select {
			case res = <-results:
			case <-time.After(20 * time.Second):
				t.Fatalf("no callback: %s", stderr.String())
			}
			cancel()
			if err = <-done; err != nil {
				t.Fatalf("serve: %v", err)
			}

			attrs := res["data"].(map[string]any)["attributes"].(map[string]any)
			if attrs["status"] != tt.wantTask {
				t.Fatalf("task result %v, want %s: %v", attrs["status"], tt.wantTask, attrs["message"])
			}
			body, err := os.ReadFile(filepath.Join(receipts, "taskrs-bobthecorp0001.receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rc struct {
				Kind      string
				Statement struct {
					Status   string
					Findings []json.RawMessage
					Run      struct{ RunnerClass string }
				}
			}
			if err = json.Unmarshal(body, &rc); err != nil {
				t.Fatal(err)
			}
			if rc.Kind != "provider-run" || rc.Statement.Status != tt.wantStatus || rc.Statement.Run.RunnerClass != "hcp-advisory" {
				t.Fatalf("receipt %s", body)
			}
			if tt.wantStatus == "single-resource-only" && len(rc.Statement.Findings) == 0 {
				t.Fatalf("no findings in %s", body)
			}
			if strings.Contains(stderr.String(), "fixture-token") || strings.Contains(stderr.String(), runtaskKey) {
				t.Fatalf("stderr carries a secret: %s", stderr.String())
			}
		})
	}
}

var listening = regexp.MustCompile(`listening on (http://\S+)`)

func waitListening(t *testing.T, stderr *lockedBuffer, done <-chan error) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := listening.FindStringSubmatch(stderr.String()); m != nil {
			return m[1]
		}
		select {
		case err := <-done:
			t.Fatalf("serve ended: %v: %s", err, stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatalf("never listened: %s", stderr.String())
	return ""
}
