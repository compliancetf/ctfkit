package hcp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const (
	testKey      = "bobthecorp-run-task-hmac-key"
	fixtureToken = "fixture-token.atlasv1.bobthecorp-not-a-real-token"
	archiveSig   = "archive-signature-secret"
	planFixture  = "../../testdata/fixtures/plan/01-raw-s3-no-ctf/input/plan.json"
	callbackPath = "/api/v2/task-results/5ea8d46c-2ceb-42cd-83f2-82e54697bddd/callback"
	planPath     = "/api/v2/plans/plan-bobthecorp0001/json-output"
	// leakyURL stands for error text a run must never pass on: a URL with a
	// signed query, as an analyzer error or a panic value might carry.
	leakySecret = "leaked-query-secret"
	leakyURL    = "https://bobthecorp.example/x?sig=" + leakySecret
)

var fixtureNow = time.Date(2026, 10, 27, 12, 1, 0, 0, time.UTC)

// syncBuffer is a log sink the runs and the test read concurrently.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeHCP is the HCP API and its archive host, both TLS on loopback. The
// plan JSON URL redirects to the archive host with a signed query, as HCP
// does; the callback records each task result.
type fakeHCP struct {
	api, archive *httptest.Server
	plan         []byte
	redirectTo   string // overrides the archive location when set
	planStatus   int

	mu          sync.Mutex
	apiAuth     []string
	archiveAuth []string
	results     []taskResult
	callbacks   chan struct{}
}

func newFakeHCP(t *testing.T) *fakeHCP {
	t.Helper()
	plan, err := os.ReadFile(planFixture)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeHCP{plan: plan, planStatus: http.StatusOK, callbacks: make(chan struct{}, 16)}
	f.archive = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.archiveAuth = append(f.archiveAuth, r.Header.Get("Authorization"))
		if r.URL.Query().Get("sig") != archiveSig {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		w.WriteHeader(f.planStatus)
		_, _ = w.Write(f.plan)
	}))
	t.Cleanup(f.archive.Close)
	f.api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.apiAuth = append(f.apiAuth, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == planPath:
			to := f.redirectTo
			if to == "" {
				to = f.archive.URL + "/archive/plan.json?sig=" + archiveSig
			}
			http.Redirect(w, r, to, http.StatusTemporaryRedirect)
		case r.Method == http.MethodPatch && r.URL.Path == callbackPath:
			if r.Header.Get("Content-Type") != jsonAPIType {
				http.Error(w, "content type", http.StatusUnsupportedMediaType)
				return
			}
			var tr taskResult
			if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
				http.Error(w, "body", http.StatusUnprocessableEntity)
				return
			}
			f.results = append(f.results, tr)
			f.callbacks <- struct{}{}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.api.Close)
	return f
}

func (f *fakeHCP) host() string { return strings.TrimPrefix(f.api.URL, "https://") }

func (f *fakeHCP) archiveHost() string { return strings.TrimPrefix(f.archive.URL, "https://") }

// waitResult waits for the next callback.
func (f *fakeHCP) waitResult(t *testing.T) taskResult {
	t.Helper()
	select {
	case <-f.callbacks:
	case <-time.After(10 * time.Second):
		t.Fatal("no callback")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.results[len(f.results)-1]
}

func (f *fakeHCP) callbackCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.results)
}

type harness struct {
	t        *testing.T
	hcp      *fakeHCP
	h        *Handler
	cfg      Config
	receipts string
	log      *syncBuffer
}

type option func(*Config)

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	f := newFakeHCP(t)
	logs := &syncBuffer{}
	cfg := Config{
		HMACKey: []byte(testKey), Hostname: f.host(), ArchiveHosts: []string{f.archiveHost()},
		MaxPlanBytes: 1 << 20, ReplayWindow: time.Hour, Timeout: 10 * time.Second, MaxConcurrent: 4,
		ReceiptDir: t.TempDir(), Generator: Generator{Name: "ctfkit", Version: "test"},
		Transport: f.api.Client().Transport,
		Profile: func(time.Time) (Profile, error) {
			return Profile{VerdictRequired: false, Digest: "sha256:profile"}, nil
		},
		Analyze: func(_ context.Context, plan *tfjson.Plan, _ ctfkit.RunMetadata) (ctfkit.Findings, error) {
			if plan == nil {
				return nil, errors.New("no plan")
			}
			return ctfkit.Findings{{RuleID: "ctf.module.raw_resource", Level: ctfkit.LevelError,
				Message: ctfkit.Message{Text: "aws_s3_bucket.logs is a raw resource."}}}, nil
		},
		Now: func() time.Time { return fixtureNow },
		Log: log.New(logs, "", 0),
	}
	for _, o := range opts {
		o(&cfg)
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	return &harness{t: t, hcp: f, h: h, cfg: cfg, receipts: cfg.ReceiptDir, log: logs}
}

// payload is a fixture with its URLs on the fake HCP host and edit applied.
func (hs *harness) payload(name string, edit func(m map[string]any)) []byte {
	hs.t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		hs.t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("https://app.terraform.io"), []byte(hs.hcp.api.URL))
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		hs.t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		hs.t.Fatal(err)
	}
	return out
}

func sign(key string, body []byte) string {
	mac := hmac.New(sha512.New, []byte(key))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// send posts body with sig and returns the status code.
func (hs *harness) send(method string, body []byte, sig string) int {
	hs.t.Helper()
	req := httptest.NewRequest(method, "/", bytes.NewReader(body))
	if sig != "" {
		req.Header.Set(SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec.Code
}

func (hs *harness) receipt(id string) map[string]any {
	hs.t.Helper()
	p := filepath.Join(hs.receipts, id+receiptSuffix)
	st, err := os.Stat(p)
	if err != nil {
		hs.t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		hs.t.Fatalf("receipt mode %v, want 0600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		hs.t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		hs.t.Fatal(err)
	}
	return m
}

func statement(m map[string]any) map[string]any { return m["statement"].(map[string]any) }

func TestNewHandlerRefuses(t *testing.T) {
	t.Parallel()
	base := func() Config {
		return Config{HMACKey: []byte(testKey), Hostname: "app.terraform.io", MaxPlanBytes: 1, ReplayWindow: 1,
			Timeout: 1, MaxConcurrent: 1, ReceiptDir: t.TempDir(),
			Profile: func(time.Time) (Profile, error) { return Profile{}, nil },
			Analyze: func(context.Context, *tfjson.Plan, ctfkit.RunMetadata) (ctfkit.Findings, error) { return nil, nil }}
	}
	tests := []struct {
		name string
		edit func(c *Config)
	}{
		{"short key", func(c *Config) { c.HMACKey = []byte("short") }},
		{"hostname with a path", func(c *Config) { c.Hostname = "app.terraform.io/evil" }},
		{"hostname with userinfo", func(c *Config) { c.Hostname = "u@app.terraform.io" }},
		{"archive host with a scheme", func(c *Config) { c.ArchiveHosts = []string{"https://x"} }},
		{"no plan limit", func(c *Config) { c.MaxPlanBytes = 0 }},
		{"no receipt dir", func(c *Config) { c.ReceiptDir = "" }},
		{"missing receipt dir", func(c *Config) { c.ReceiptDir = filepath.Join(c.ReceiptDir, "absent") }},
		{"no analyzer", func(c *Config) { c.Analyze = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := base()
			tt.edit(&c)
			if h, err := NewHandler(c); err == nil {
				_ = h.Close(context.Background())
				t.Fatal("accepted")
			}
		})
	}
}

// TestServeHTTPRejects: every request that fails a check is answered with
// its status and never reaches HCP.
func TestServeHTTPRejects(t *testing.T) {
	t.Parallel()
	hs := newHarness(t)
	good := hs.payload("post-plan.json", nil)
	edited := func(edit func(m map[string]any)) []byte { return hs.payload("post-plan.json", edit) }
	tests := []struct {
		name   string
		method string
		body   []byte
		sig    string
		want   int
	}{
		{"no signature", http.MethodPost, good, "", http.StatusUnauthorized},
		{"wrong key", http.MethodPost, good, sign("another-key-of-enough-length", good), http.StatusUnauthorized},
		{"signature of other bytes", http.MethodPost, good, sign(testKey, append([]byte(" "), good...)), http.StatusUnauthorized},
		{"truncated signature", http.MethodPost, good, sign(testKey, good)[:64], http.StatusUnauthorized},
		{"not hex", http.MethodPost, good, strings.Repeat("zz", sha512.Size), http.StatusUnauthorized},
		{"GET", http.MethodGet, good, sign(testKey, good), http.StatusMethodNotAllowed},
		{"over 1 MiB", http.MethodPost, make([]byte, maxPayloadBytes+1), strings.Repeat("00", sha512.Size), http.StatusRequestEntityTooLarge},
	}
	reject := func(name, why string, edit func(m map[string]any), want int) {
		b := edited(edit)
		tests = append(tests, struct {
			name   string
			method string
			body   []byte
			sig    string
			want   int
		}{name + ": " + why, http.MethodPost, b, sign(testKey, b), want})
	}
	reject("stale run", "replay window", func(m map[string]any) { m["run_created_at"] = "2026-10-27T10:00:00Z" }, http.StatusUnauthorized)
	reject("future run", "replay window", func(m map[string]any) { m["run_created_at"] = "2026-10-27T13:00:00Z" }, http.StatusUnauthorized)
	reject("pre_plan", "no plan JSON", func(m map[string]any) { m["stage"] = "pre_plan" }, http.StatusUnprocessableEntity)
	reject("payload v2", "version", func(m map[string]any) { m["payload_version"] = 2 }, http.StatusUnprocessableEntity)
	reject("enforcement", "unknown", func(m map[string]any) { m["task_result_enforcement_level"] = "soft" }, http.StatusUnprocessableEntity)
	reject("plan URL", "http", func(m map[string]any) {
		m["plan_json_api_url"] = strings.Replace(m["plan_json_api_url"].(string), "https://", "http://", 1)
	}, http.StatusUnprocessableEntity)
	reject("plan URL", "another host", func(m map[string]any) {
		m["plan_json_api_url"] = "https://169.254.169.254" + planPath
	}, http.StatusUnprocessableEntity)
	reject("plan URL", "another path", func(m map[string]any) {
		m["plan_json_api_url"] = hs.hcp.api.URL + "/api/v2/state-versions/sv-1/download"
	}, http.StatusUnprocessableEntity)
	reject("plan URL", "dot segments", func(m map[string]any) {
		m["plan_json_api_url"] = hs.hcp.api.URL + "/api/v2/plans/../../admin/json-output"
	}, http.StatusUnprocessableEntity)
	reject("plan URL", "query", func(m map[string]any) {
		m["plan_json_api_url"] = hs.hcp.api.URL + planPath + "?x=1"
	}, http.StatusUnprocessableEntity)
	reject("plan URL", "userinfo", func(m map[string]any) {
		m["plan_json_api_url"] = "https://u:p@" + hs.hcp.host() + planPath
	}, http.StatusUnprocessableEntity)
	reject("callback URL", "another host", func(m map[string]any) {
		m["task_result_callback_url"] = hs.hcp.archive.URL + callbackPath
	}, http.StatusUnprocessableEntity)
	reject("task result id", "path", func(m map[string]any) { m["task_result_id"] = "../../etc/passwd" }, http.StatusUnprocessableEntity)
	reject("access token", "empty", func(m map[string]any) { m["access_token"] = "" }, http.StatusUnprocessableEntity)

	for _, tt := range tests {
		if got := hs.send(tt.method, tt.body, tt.sig); got != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, got, tt.want)
		}
	}
	if n := hs.hcp.callbackCount(); n != 0 {
		t.Fatalf("%d callbacks for rejected requests", n)
	}
	hs.hcp.mu.Lock()
	defer hs.hcp.mu.Unlock()
	if len(hs.hcp.apiAuth)+len(hs.hcp.archiveAuth) != 0 {
		t.Fatal("a rejected request reached HCP")
	}
}

// TestServeHTTPVerification: the request HCP sends when a run task is saved
// is answered 200 once signed, with no callback; unsigned it is 401.
func TestServeHTTPVerification(t *testing.T) {
	t.Parallel()
	hs := newHarness(t)
	body := hs.payload("verification.json", nil)
	if got := hs.send(http.MethodPost, body, sign("not-the-key-at-all-0", body)); got != http.StatusUnauthorized {
		t.Fatalf("unsigned verification: %d", got)
	}
	if got := hs.send(http.MethodPost, body, sign(testKey, body)); got != http.StatusOK {
		t.Fatalf("verification: %d", got)
	}
	if err := hs.h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := hs.hcp.callbackCount(); n != 0 {
		t.Fatalf("%d callbacks for a verification request", n)
	}
}

// TestServeHTTPReplay: a signed request accepted once is an idempotent
// retry the second time, also for a new handler over the same receipt dir:
// 200, no new run, no second callback, a duplicate log line.
func TestServeHTTPReplay(t *testing.T) {
	t.Parallel()
	hs := newHarness(t)
	body := hs.payload("post-plan.json", nil)
	sig := sign(testKey, body)
	if got := hs.send(http.MethodPost, body, sig); got != http.StatusOK {
		t.Fatalf("first: %d", got)
	}
	if got := hs.send(http.MethodPost, body, sig); got != http.StatusOK {
		t.Fatalf("retry while running: %d, want 200", got)
	}
	hs.hcp.waitResult(t)
	if got := hs.send(http.MethodPost, body, sig); got != http.StatusOK {
		t.Fatalf("retry after the run: %d, want 200", got)
	}
	if err := hs.h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(hs.log.String(), "duplicate request"); n != 2 {
		t.Fatalf("%d duplicate log lines, want 2: %s", n, hs.log.String())
	}
	restarted, err := NewHandler(hs.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close(context.Background()) //nolint:errcheck // test cleanup
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, sig)
	restarted.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry after restart: %d, want 200", rec.Code)
	}
	if err = restarted.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := hs.hcp.callbackCount(); n != 1 {
		t.Fatalf("%d callbacks, want 1", n)
	}
}

// TestRunAdvisory: a profile without verdict_required gets a
// single-resource-only receipt and no verdict; the token goes to the API
// host only; mandatory enforcement fails on an error finding, advisory
// passes.
func TestRunAdvisory(t *testing.T) {
	t.Parallel()
	for _, level := range []string{enforcementMandatory, enforcementAdvisory} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			hs := newHarness(t)
			body := hs.payload("post-plan.json", func(m map[string]any) { m["task_result_enforcement_level"] = level })
			if got := hs.send(http.MethodPost, body, sign(testKey, body)); got != http.StatusOK {
				t.Fatalf("status %d", got)
			}
			res := hs.hcp.waitResult(t)
			want := taskPassed
			if level == enforcementMandatory {
				want = taskFailed
			}
			if res.Data.Attributes.Status != want {
				t.Fatalf("task result %q, want %q (%s)", res.Data.Attributes.Status, want, res.Data.Attributes.Message)
			}
			if res.Data.Relationships == nil || len(res.Data.Relationships.Outcomes.Data) != 1 {
				t.Fatalf("outcomes: %+v", res.Data.Relationships)
			}
			hs.hcp.mu.Lock()
			apiAuth, archiveAuth := hs.hcp.apiAuth, hs.hcp.archiveAuth
			hs.hcp.mu.Unlock()
			for _, a := range apiAuth {
				if a != "Bearer "+fixtureToken {
					t.Fatalf("API call authorization %q", a)
				}
			}
			if len(archiveAuth) != 1 || archiveAuth[0] != "" {
				t.Fatalf("archive host got authorization %q", archiveAuth)
			}

			st := statement(hs.receipt("taskrs-bobthecorp0001"))
			if st["status"] != statusSingleResource {
				t.Fatalf("receipt status %v", st["status"])
			}
			run := st["run"].(map[string]any)
			if run["runnerClass"] != runnerClass || run["orgId"] != "bobthecorp" {
				t.Fatalf("receipt run %v", run)
			}
			if _, ok := st["verdict"]; ok {
				t.Fatal("receipt carries a verdict")
			}
			if in := st["inputs"].(map[string]any); !strings.HasPrefix(in["planJson"].(string), "sha256:") {
				t.Fatalf("receipt inputs %v", in)
			}
			entries, err := os.ReadDir(hs.receipts)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("receipt dir holds %d files, want the receipt only", len(entries))
			}
			for _, secret := range []string{fixtureToken, archiveSig, testKey} {
				if strings.Contains(hs.log.String(), secret) {
					t.Fatalf("log carries a secret: %s", hs.log.String())
				}
			}
		})
	}
}

// TestRunVerdictRequired: under verdict_required a mutating run fails
// closed; a speculative run cannot apply and stays single-resource-only.
func TestRunVerdictRequired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		speculative bool
		want        string
	}{
		{"mutating", false, statusFailed},
		{"speculative", true, statusSingleResource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hs := newHarness(t, func(c *Config) {
				c.Profile = func(time.Time) (Profile, error) { return Profile{VerdictRequired: true}, nil }
				c.Analyze = func(context.Context, *tfjson.Plan, ctfkit.RunMetadata) (ctfkit.Findings, error) { return nil, nil }
			})
			body := hs.payload("post-plan.json", func(m map[string]any) {
				m["is_speculative"] = tt.speculative
				m["task_result_enforcement_level"] = enforcementAdvisory
			})
			if got := hs.send(http.MethodPost, body, sign(testKey, body)); got != http.StatusOK {
				t.Fatalf("status %d", got)
			}
			res := hs.hcp.waitResult(t)
			wantTask := taskPassed
			if tt.want == statusFailed {
				wantTask = taskFailed
			}
			if res.Data.Attributes.Status != wantTask {
				t.Fatalf("task result %q, want %q", res.Data.Attributes.Status, wantTask)
			}
			if st := statement(hs.receipt("taskrs-bobthecorp0001")); st["status"] != tt.want {
				t.Fatalf("receipt status %v, want %s", st["status"], tt.want)
			}
			// The check ran: a verdict_required refusal never reads as an outage.
			if strings.Contains(res.Data.Attributes.Message, "did not run") {
				t.Fatalf("message %q", res.Data.Attributes.Message)
			}
		})
	}
}

// TestRunFailsClosed: a run that cannot be evaluated reports failed under
// advisory enforcement too, and its receipt says failed.
func TestRunFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		opt    option
		fake   func(f *fakeHCP)
		reason string
	}{
		{"plan over the limit", func(c *Config) { c.MaxPlanBytes = 100 }, nil, "plan download failed (over the 100 byte limit)"},
		{"redirect off the allowed hosts", func(c *Config) { c.ArchiveHosts = nil }, nil, "plan download failed;"},
		{"redirect to http", nil, func(f *fakeHCP) {
			f.redirectTo = strings.Replace(f.archive.URL, "https://", "http://", 1) + "/archive/plan.json?sig=" + archiveSig
		}, "plan download failed;"},
		{"plan download error", nil, func(f *fakeHCP) { f.planStatus = http.StatusInternalServerError }, "plan download failed (HTTP 500)"},
		{"not a plan", nil, func(f *fakeHCP) { f.plan = []byte(`{"format_version":"2.0"}`) }, "plan JSON not readable"},
		{"profile refused", func(c *Config) {
			c.Profile = func(time.Time) (Profile, error) { return Profile{}, errors.New("floor expired") }
		}, nil, "profile refused"},
		{"analyzer error", func(c *Config) {
			c.Analyze = func(context.Context, *tfjson.Plan, ctfkit.RunMetadata) (ctfkit.Findings, error) {
				return nil, errors.New("GET " + leakyURL + " failed")
			}
		}, nil, "analyzer error"},
		{"analyzer panic", func(c *Config) {
			c.Analyze = func(context.Context, *tfjson.Plan, ctfkit.RunMetadata) (ctfkit.Findings, error) {
				panic("analyzer bug at " + leakyURL)
			}
		}, nil, "analyzer panic"},
		{"timeout", func(c *Config) {
			c.Timeout = 50 * time.Millisecond
			c.Analyze = func(ctx context.Context, _ *tfjson.Plan, _ ctfkit.RunMetadata) (ctfkit.Findings, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}, nil, "run timed out"}, // the deadline may end the download or the analyzers
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var opts []option
			if tt.opt != nil {
				opts = append(opts, tt.opt)
			}
			hs := newHarness(t, opts...)
			if tt.fake != nil {
				hs.hcp.mu.Lock()
				tt.fake(hs.hcp)
				hs.hcp.mu.Unlock()
			}
			body := hs.payload("post-plan.json", func(m map[string]any) { m["task_result_enforcement_level"] = enforcementAdvisory })
			if got := hs.send(http.MethodPost, body, sign(testKey, body)); got != http.StatusOK {
				t.Fatalf("status %d", got)
			}
			res := hs.hcp.waitResult(t)
			msg := res.Data.Attributes.Message
			if res.Data.Attributes.Status != taskFailed || !strings.Contains(msg, tt.reason) || !strings.Contains(msg, "the check did not run") {
				t.Fatalf("task result %q %q", res.Data.Attributes.Status, msg)
			}
			st := statement(hs.receipt("taskrs-bobthecorp0001"))
			if st["status"] != statusFailed || !strings.Contains(st["reason"].(string), "the check did not run") {
				t.Fatalf("receipt status %v reason %v", st["status"], st["reason"])
			}
			// No raw error text or panic value reaches HCP, the receipt or the log.
			callback, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(filepath.Join(hs.receipts, "taskrs-bobthecorp0001"+receiptSuffix))
			if err != nil {
				t.Fatal(err)
			}
			for where, text := range map[string]string{"callback": string(callback), "receipt": string(receipt), "log": hs.log.String()} {
				for _, secret := range []string{leakySecret, "analyzer bug", archiveSig, fixtureToken} {
					if strings.Contains(text, secret) {
						t.Fatalf("%s carries %q: %s", where, secret, text)
					}
				}
			}
			if strings.HasPrefix(tt.name, "redirect") {
				hs.hcp.mu.Lock()
				defer hs.hcp.mu.Unlock()
				if len(hs.hcp.archiveAuth) != 0 {
					t.Fatal("a refused redirect reached the archive host")
				}
			}
		})
	}
}

// TestServeHTTPBusy: a request beyond MaxConcurrent answers 503 and is not
// recorded, so HCP's retry is accepted.
func TestServeHTTPBusy(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	hs := newHarness(t, func(c *Config) {
		c.MaxConcurrent = 1
		c.Analyze = func(context.Context, *tfjson.Plan, ctfkit.RunMetadata) (ctfkit.Findings, error) {
			<-release
			return nil, nil
		}
	})
	first := hs.payload("post-plan.json", nil)
	second := hs.payload("post-plan.json", func(m map[string]any) { m["task_result_id"] = "taskrs-bobthecorp0002" })
	if got := hs.send(http.MethodPost, first, sign(testKey, first)); got != http.StatusOK {
		t.Fatalf("first: %d", got)
	}
	if got := hs.send(http.MethodPost, second, sign(testKey, second)); got != http.StatusServiceUnavailable {
		t.Fatalf("busy: %d, want 503", got)
	}
	close(release)
	hs.hcp.waitResult(t)
	deadline := time.Now().Add(5 * time.Second)
	for hs.send(http.MethodPost, second, sign(testKey, second)) != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("the retry was never accepted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hs.hcp.waitResult(t)
}

// TestServeHTTPSlowBodiesDoNotStarveSigned: unauthenticated peers trickling
// small bodies on every read slot do not turn a signed request away with 503.
func TestServeHTTPSlowBodiesDoNotStarveSigned(t *testing.T) {
	t.Parallel()
	hs := newHarness(t)
	var wg sync.WaitGroup
	writers := make([]*io.PipeWriter, 0, maxRequests)
	for range maxRequests {
		pr, pw := io.Pipe()
		writers = append(writers, pw)
		req := httptest.NewRequest(http.MethodPost, "/", pr)
		req.Header.Set(SignatureHeader, strings.Repeat("a", 2*sha512.Size))
		wg.Go(func() { hs.h.ServeHTTP(httptest.NewRecorder(), req) })
		if _, err := pw.Write([]byte("{")); err != nil { // returns once the handler reads the body
			t.Fatal(err)
		}
	}
	body := hs.payload("verification.json", nil)
	got := hs.send(http.MethodPost, body, sign(testKey, body))
	for _, pw := range writers {
		_ = pw.Close()
	}
	wg.Wait()
	if got != http.StatusOK {
		t.Fatalf("signed request while slow bodies are read: %d, want 200", got)
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()
	_, err := http.Get("https://127.0.0.1:1/x?sig=" + archiveSig) //nolint:noctx // a refused dial
	if err == nil {
		t.Skip("port 1 answered")
	}
	if got := redact(err).Error(); strings.Contains(got, archiveSig) || !strings.Contains(got, "127.0.0.1:1") {
		t.Fatalf("redact: %q", got)
	}
}
