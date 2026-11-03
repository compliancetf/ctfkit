// Package hcp is the HCP Terraform and Terraform Enterprise run task adapter
// behind `ctfkit runtask serve` (preview). It runs in advisory mode only: it
// verifies the run task request, downloads the plan JSON of the run, runs the
// post_plan analyzers over it, writes a provider-run receipt and posts the
// task result back. It never produces a verdict: HCP and TFE run terraform
// plan themselves, so no gate-owned candidate exists for a gate to sign.
//
// The request is untrusted until its HMAC verifies. After that the payload
// is still checked before any outbound call: the plan JSON and callback URLs
// must be https URLs on the configured host with the run task API path, so a
// signed payload cannot point ctfkit at another service, and the access
// token is only ever sent to that host.
package hcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const (
	// SignatureHeader carries the hex HMAC-SHA512 of the request body.
	SignatureHeader = "X-TFC-Task-Signature"
	// verificationToken is the access token of the request HCP sends when a
	// run task is created or edited; it is answered 200 and nothing else.
	verificationToken = "test-token"

	maxPayloadBytes = 1 << 20 // a run task request is a few KiB
	maxTokenBytes   = 4096    // access_token
	maxSeen         = 100_000 // task results remembered for replay protection
	maxRequests     = 64      // request bodies read at once
	futureSkew      = 5 * time.Minute
	minHMACKeyBytes = 16
)

// Stages that carry a plan JSON URL.
const (
	stagePostPlan = "post_plan"
	stagePreApply = "pre_apply"
)

// Enforcement levels HCP sends.
const (
	enforcementMandatory = "mandatory"
	enforcementAdvisory  = "advisory"
)

// Profile is what the verified org profile tells a run task.
type Profile struct {
	// VerdictRequired is the profile's verdict_required.
	VerdictRequired bool
	// Digest is the profile digest the receipt names.
	Digest string
}

// Config configures a Handler. Every field without a default is required.
type Config struct {
	// HMACKey is the run task HMAC key, at least 16 bytes.
	HMACKey []byte
	// Hostname is the HCP or TFE host (host or host:port) every payload URL
	// must be on, app.terraform.io for HCP Terraform.
	Hostname string
	// ArchiveHosts are the extra hosts a plan JSON download may be
	// redirected to (archivist.terraform.io for HCP Terraform). The access
	// token is never sent to them.
	ArchiveHosts []string
	// MaxPlanBytes bounds a downloaded plan JSON.
	MaxPlanBytes int64
	// ReplayWindow is how far run_created_at may lie in the past.
	ReplayWindow time.Duration
	// Timeout bounds one run from acceptance to callback; keep it below the
	// 10 minute progress limit of HCP.
	Timeout time.Duration
	// MaxConcurrent bounds runs in flight; a request beyond it answers 503.
	MaxConcurrent int
	// ReceiptDir is the directory each run's receipt is written to.
	ReceiptDir string
	// Generator names the build, for the receipt.
	Generator Generator
	// Transport is the base transport of outbound calls; nil uses one with
	// dial, TLS handshake and response header timeouts.
	Transport http.RoundTripper
	// Profile returns the verified org profile at now; an error fails the
	// run closed.
	Profile func(now time.Time) (Profile, error)
	// Analyze runs the post_plan analyzers over a plan.
	Analyze func(ctx context.Context, plan *tfjson.Plan, md ctfkit.RunMetadata) (ctfkit.Findings, error)
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// Log receives one line per rejected request and per run. It never
	// receives a token, a key or a download URL.
	Log *log.Logger
}

// Handler serves run task requests. Close it to wait for runs in flight.
type Handler struct {
	cfg      Config
	plan     *http.Client
	callback *http.Client
	slots    chan struct{}
	requests chan struct{}
	receipts *os.Root
	base     context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	seen    map[string]time.Time // task_result_id to run_created_at
	allowed map[string]bool      // hosts a plan JSON download may reach
}

// NewHandler checks cfg and returns a Handler.
func NewHandler(cfg Config) (*Handler, error) {
	switch {
	case len(cfg.HMACKey) < minHMACKeyBytes:
		return nil, fmt.Errorf("the HMAC key must be at least %d bytes", minHMACKeyBytes)
	case !validHost(cfg.Hostname):
		return nil, fmt.Errorf("hostname %q is not a host or host:port", cfg.Hostname)
	case cfg.MaxPlanBytes <= 0, cfg.ReplayWindow <= 0, cfg.Timeout <= 0, cfg.MaxConcurrent <= 0:
		return nil, errors.New("max plan bytes, replay window, timeout and max concurrent must be positive")
	case cfg.ReceiptDir == "":
		return nil, errors.New("no receipt directory")
	case cfg.Profile == nil || cfg.Analyze == nil:
		return nil, errors.New("no profile or analyzer function")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.New(io.Discard, "", 0)
	}
	allowed := map[string]bool{cfg.Hostname: true}
	for _, h := range cfg.ArchiveHosts {
		if !validHost(h) {
			return nil, fmt.Errorf("archive host %q is not a host or host:port", h)
		}
		allowed[h] = true
	}
	if cfg.Transport == nil {
		cfg.Transport = &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  30 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			ForceAttemptHTTP2:      true,
		}
	}
	receipts, err := os.OpenRoot(cfg.ReceiptDir)
	if err != nil {
		return nil, fmt.Errorf("receipt directory: %w", err)
	}
	base, cancel := context.WithCancel(context.Background())
	h := &Handler{cfg: cfg, slots: make(chan struct{}, cfg.MaxConcurrent), requests: make(chan struct{}, maxRequests),
		receipts: receipts, base: base, cancel: cancel,
		seen: map[string]time.Time{}, allowed: allowed}
	h.plan = &http.Client{Transport: cfg.Transport, Timeout: cfg.Timeout, CheckRedirect: h.planRedirect}
	// The callback has its own limit: a run that used up Timeout still
	// reports failed.
	h.callback = &http.Client{Transport: cfg.Transport, Timeout: callbackTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h, nil
}

// Close stops accepting runs and waits for those in flight until ctx ends,
// then cancels them and waits for them to finish.
func (h *Handler) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		h.cancel()
		<-done
		err = ctx.Err()
	}
	h.cancel()
	return errors.Join(err, h.receipts.Close())
}

// payload is the part of a run task request ctfkit reads.
type payload struct {
	PayloadVersion int    `json:"payload_version"`
	Stage          string `json:"stage"`
	AccessToken    string `json:"access_token"`
	Capabilities   struct {
		Outcomes bool `json:"outcomes"`
	} `json:"capabilities"`
	IsSpeculative    bool      `json:"is_speculative"`
	OrganizationName string    `json:"organization_name"`
	PlanJSONAPIURL   string    `json:"plan_json_api_url"`
	RunCreatedAt     time.Time `json:"run_created_at"`
	RunID            string    `json:"run_id"`
	CallbackURL      string    `json:"task_result_callback_url"`
	Enforcement      string    `json:"task_result_enforcement_level"`
	TaskResultID     string    `json:"task_result_id"`
	WorkspaceName    string    `json:"workspace_name"`
}

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	namePattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	planPathPattern = regexp.MustCompile(`^/api/v2/plans/[A-Za-z0-9_-]{1,128}/json-output$`)
	callbackPattern = regexp.MustCompile(`^/api/v2/task-results/[A-Za-z0-9_-]{1,128}/callback$`)
)

// ServeHTTP answers a run task request: 401 for a bad signature or a stale
// run, 422 for a payload ctfkit cannot act on, 503 when busy, and 200 once
// the run is accepted. A task result already accepted is HCP retrying a
// request whose answer it did not see: 200 again, with no new run and no
// second callback. The run itself happens after the answer and ends in the
// callback.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.reject(w, r, http.StatusMethodNotAllowed, "method "+r.Method)
		return
	}
	// Unauthenticated work stays small: a bounded number of bodies are read
	// at once, and none without a signature of the right shape.
	select {
	case h.requests <- struct{}{}:
		defer func() { <-h.requests }()
	default:
		h.reject(w, r, http.StatusServiceUnavailable, "too many requests being read")
		return
	}
	if len(r.Header.Get(SignatureHeader)) != 2*sha512.Size {
		h.reject(w, r, http.StatusUnauthorized, "signature missing or invalid")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPayloadBytes))
	if err != nil {
		h.reject(w, r, http.StatusRequestEntityTooLarge, "request body unreadable or over 1 MiB")
		return
	}
	if !h.signed(body, r.Header.Get(SignatureHeader)) {
		h.reject(w, r, http.StatusUnauthorized, "signature missing or invalid")
		return
	}
	var p payload
	if err = json.Unmarshal(body, &p); err != nil {
		h.reject(w, r, http.StatusUnprocessableEntity, "payload is not run task JSON")
		return
	}
	if p.AccessToken == verificationToken {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err = h.check(&p); err != nil {
		h.reject(w, r, http.StatusUnprocessableEntity, err.Error())
		return
	}
	status, why := h.accept(&p)
	if status == http.StatusOK && why != "" {
		h.cfg.Log.Printf("runtask: duplicate request from %s: %s", r.RemoteAddr, why)
	}
	if status != http.StatusOK {
		h.reject(w, r, status, why)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request, status int, why string) {
	h.cfg.Log.Printf("runtask: rejected a request from %s: %d %s", r.RemoteAddr, status, clip(why))
	http.Error(w, http.StatusText(status), status)
}

// signed reports whether sig is the hex HMAC-SHA512 of body, compared in
// constant time. An empty or malformed header never verifies.
func (h *Handler) signed(body []byte, sig string) bool {
	got, err := hex.DecodeString(sig)
	if err != nil || len(got) != sha512.Size {
		return false
	}
	mac := hmac.New(sha512.New, h.cfg.HMACKey)
	_, _ = mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

// check validates a signed payload before any outbound call.
func (h *Handler) check(p *payload) error {
	switch {
	case p.PayloadVersion != 1:
		return fmt.Errorf("payload_version %d is not 1", p.PayloadVersion)
	case p.Stage != stagePostPlan && p.Stage != stagePreApply:
		return fmt.Errorf("stage %q has no plan JSON; configure the run task for post_plan or pre_apply", p.Stage)
	case p.Enforcement != enforcementMandatory && p.Enforcement != enforcementAdvisory:
		return fmt.Errorf("task_result_enforcement_level %q is not mandatory or advisory", p.Enforcement)
	case p.AccessToken == "" || len(p.AccessToken) > maxTokenBytes:
		return errors.New("access_token is empty or too long")
	case !idPattern.MatchString(p.RunID), !idPattern.MatchString(p.TaskResultID):
		return errors.New("run_id or task_result_id is not an id")
	case !namePattern.MatchString(p.OrganizationName), !namePattern.MatchString(p.WorkspaceName):
		return errors.New("organization_name or workspace_name is not a name")
	case p.RunCreatedAt.IsZero():
		return errors.New("run_created_at is missing")
	}
	if err := h.apiURL(p.PlanJSONAPIURL, planPathPattern); err != nil {
		return fmt.Errorf("plan_json_api_url: %w", err)
	}
	if err := h.apiURL(p.CallbackURL, callbackPattern); err != nil {
		return fmt.Errorf("task_result_callback_url: %w", err)
	}
	return nil
}

// apiURL accepts only an https URL on the configured host whose path is the
// run task API path, with no userinfo, query or fragment.
func (h *Handler) apiURL(raw string, path *regexp.Regexp) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("not a URL")
	case u.Scheme != "https":
		return errors.New("not https")
	case u.Host != h.cfg.Hostname:
		return fmt.Errorf("host %q is not the configured host %q", u.Host, h.cfg.Hostname)
	case u.User != nil, u.RawQuery != "", u.Fragment != "", u.Opaque != "":
		return errors.New("carries userinfo, a query or a fragment")
	case !path.MatchString(u.EscapedPath()):
		return errors.New("path is not the run task API path")
	}
	return nil
}

// accept applies the replay window and the duplicate check, takes a run
// slot and starts the run. A task result is recorded only when its run
// starts, so a retry of a request answered 503 is not a replay.
func (h *Handler) accept(p *payload) (int, string) {
	now := h.cfg.Now()
	created := p.RunCreatedAt
	if created.Before(now.Add(-h.cfg.ReplayWindow)) || created.After(now.Add(futureSkew)) {
		return http.StatusUnauthorized, "replay: run_created_at is outside the replay window"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return http.StatusServiceUnavailable, "shutting down"
	}
	for id, at := range h.seen {
		if at.Before(now.Add(-h.cfg.ReplayWindow)) {
			delete(h.seen, id) // the window check rejects it now
		}
	}
	if _, dup := h.seen[p.TaskResultID]; dup || h.receiptExists(p.TaskResultID) {
		return http.StatusOK, "task result " + p.TaskResultID + " was already accepted; no new run"
	}
	if len(h.seen) >= maxSeen {
		return http.StatusServiceUnavailable, "replay cache full"
	}
	select {
	case h.slots <- struct{}{}:
	default:
		return http.StatusServiceUnavailable, "too many runs in flight"
	}
	h.seen[p.TaskResultID] = created
	h.wg.Add(1)
	go func(p payload) {
		defer func() { <-h.slots; h.wg.Done() }()
		defer func() {
			if r := recover(); r != nil { // one run's bug must not stop the server
				h.cfg.Log.Printf("runtask: run %s: internal error: %v", p.RunID, r)
			}
		}()
		ctx, cancel := context.WithTimeout(h.base, h.cfg.Timeout)
		defer cancel()
		h.run(ctx, &p)
	}(*p)
	return http.StatusOK, ""
}

// validHost accepts host or host:port with no other URL part.
func validHost(h string) bool {
	u, err := url.Parse("https://" + h)
	return err == nil && h != "" && u.Host == h && u.Path == "" && u.User == nil
}
