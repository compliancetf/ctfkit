package hcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

const (
	maxRedirects    = 3
	maxOutcomes     = 50
	maxMessageRunes = 500
	maxCalloutBody  = 64 << 10 // callback response bytes read
	callbackTimeout = 30 * time.Second
	jsonAPIType     = "application/vnd.api+json"
	platformHCP     = "hcp-terraform"
)

// Task result statuses.
const (
	taskPassed = "passed"
	taskFailed = "failed"
)

// outcome is what one run decided.
type outcome struct {
	status     string // receipt status
	conditions []string
	reason     string // why a failed run failed, empty otherwise
	findings   ctfkit.Findings
	planDigest string
	profile    string
	blocking   bool // an unsuppressed error-level finding
}

// run evaluates one accepted request, writes its receipt and posts the task
// result. A run that cannot finish its evaluation fails closed.
func (h *Handler) run(ctx context.Context, p *payload) {
	now := h.cfg.Now()
	o := h.safeEvaluate(ctx, p)
	if err := h.writeReceipt(p, o, now); err != nil {
		h.cfg.Log.Printf("runtask: run %s: writing the receipt: %v", p.RunID, err)
		o = failed(o, "the check ran, but its receipt could not be written, so this run has no evidence")
	}
	result := h.taskResult(p, o)
	// The callback has its own deadline and outlives a forced Close, so a
	// run that timed out or was stopped still reports instead of leaving
	// the task pending.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), callbackTimeout)
	defer cancel()
	if err := h.post(cctx, p, result); err != nil {
		h.cfg.Log.Printf("runtask: run %s: callback: %v", p.RunID, err)
		return
	}
	h.cfg.Log.Printf("runtask: run %s task result %s: %s, receipt %s", p.RunID, p.TaskResultID, result.Data.Attributes.Status, o.status)
}

// safeEvaluate is evaluate with a panic turned into a failed run, so one
// bad plan neither stops the server nor leaves its task pending.
func (h *Handler) safeEvaluate(ctx context.Context, p *payload) (o outcome) {
	defer func() {
		if r := recover(); r != nil {
			// The panic value can carry anything; only its type is logged.
			h.cfg.Log.Printf("runtask: run %s: %s (%T)", p.RunID, notRunInternal, r)
			o = notRun(ctx, outcome{}, notRunInternal, "")
		}
	}()
	return h.evaluate(ctx, p)
}

// Categories of a run that did not run. The receipt and the task result
// carry only these and value-free details (an HTTP status, a byte limit),
// never error text or a panic value: those can hold URLs, tokens or plan
// content.
const (
	notRunProfile  = "profile refused"
	notRunDownload = "plan download failed"
	notRunPlan     = "plan JSON not readable"
	notRunAnalyzer = "analyzer error"
	notRunPanic    = "analyzer panic"
	notRunTimeout  = "run timed out"
	notRunInternal = "internal error"
)

// detail is a value-free error detail fetchPlan may give.
type detail string

func (d detail) Error() string { return string(d) }

// evaluate decides one run. It never returns a verdict: an HCP or TFE plan
// has no gate-owned provenance. Log lines carry raw errors only where they
// are local (the signed inputs) or passed through redact (the download).
func (h *Handler) evaluate(ctx context.Context, p *payload) outcome {
	o := outcome{}
	prof, err := h.cfg.Profile(h.cfg.Now())
	if err != nil {
		h.cfg.Log.Printf("runtask: run %s: %s: %v", p.RunID, notRunProfile, err)
		return notRun(ctx, o, notRunProfile, "")
	}
	o.profile = prof.Digest
	raw, err := h.fetchPlan(ctx, p)
	if err != nil {
		h.cfg.Log.Printf("runtask: run %s: %s: %v", p.RunID, notRunDownload, err)
		var d detail
		_ = errors.As(err, &d)
		return notRun(ctx, o, notRunDownload, string(d))
	}
	sum := sha256.Sum256(raw)
	o.planDigest = "sha256:" + hex.EncodeToString(sum[:])
	plan, err := loader.ParsePlanNamed("plan JSON of run "+p.RunID, raw)
	if err != nil {
		h.cfg.Log.Printf("runtask: run %s: %s", p.RunID, notRunPlan)
		return notRun(ctx, o, notRunPlan, "")
	}
	md := ctfkit.RunMetadata{RunID: p.RunID, Platform: platformHCP, Now: h.cfg.Now().UTC()}
	var panicked bool
	if o.findings, panicked, err = h.analyze(ctx, plan, md); panicked || err != nil {
		category := notRunAnalyzer
		if panicked {
			category = notRunPanic
		}
		h.cfg.Log.Printf("runtask: run %s: %s", p.RunID, category)
		return notRun(ctx, o, category, "")
	}
	o.blocking = blocking(o.findings)
	if prof.VerdictRequired && !p.IsSpeculative && mutating(plan) {
		return failed(o, "the org profile sets verdict_required and an HCP or TFE run has no gate verdict, "+
			"so this mutating run fails closed; apply through CI with ctfkit apply")
	}
	o.status = statusSingleResource
	o.conditions = []string{statusSingleResource}
	return o
}

func failed(o outcome, reason string) outcome {
	o.status, o.conditions, o.reason = statusFailed, []string{statusFailed}, reason
	return o
}

// analyze runs the analyzers with a panic reported apart from an error.
func (h *Handler) analyze(ctx context.Context, plan *tfjson.Plan, md ctfkit.RunMetadata) (fs ctfkit.Findings, panicked bool, err error) {
	defer func() {
		if recover() != nil {
			fs, panicked, err = nil, true, nil
		}
	}()
	fs, err = h.cfg.Analyze(ctx, plan, md)
	return fs, false, err
}

// notRun is a run failed closed on an infrastructure error. Its reason says
// the check did not run, so nobody reads it as failing on findings, and it
// names a fixed category with at most a value-free detail.
func notRun(ctx context.Context, o outcome, category, detail string) outcome {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		category, detail = notRunTimeout, ""
	}
	if detail != "" {
		category += " (" + detail + ")"
	}
	return failed(o, "the check did not run: "+category+"; this is not a finding about the plan")
}

// blocking reports an unsuppressed error-level finding.
func blocking(fs ctfkit.Findings) bool {
	for _, f := range fs {
		if f.Level == ctfkit.LevelError && !f.Suppressed() {
			return true
		}
	}
	return false
}

// mutating reports a resource change other than no-op or read.
func mutating(plan *tfjson.Plan) bool {
	for _, rc := range plan.ResourceChanges {
		if rc == nil || rc.Change == nil {
			return true // an entry ctfkit cannot read counts as a change
		}
		if !rc.Change.Actions.NoOp() && !rc.Change.Actions.Read() {
			return true
		}
	}
	return false
}

// fetchPlan downloads the run's plan JSON with the run's token, within the
// size limit. Redirects stay on the configured hosts, and the token goes to
// the API host only.
func (h *Handler) fetchPlan(ctx context.Context, p *payload) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.PlanJSONAPIURL, nil)
	if err != nil {
		return nil, redact(err)
	}
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := h.plan.Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, detail(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
	overLimit := detail(fmt.Sprintf("over the %d byte limit", h.cfg.MaxPlanBytes))
	if resp.ContentLength > h.cfg.MaxPlanBytes {
		return nil, overLimit
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, h.cfg.MaxPlanBytes+1))
	if err != nil {
		return nil, redact(err)
	}
	if int64(len(raw)) > h.cfg.MaxPlanBytes {
		return nil, overLimit
	}
	return raw, nil
}

// planRedirect allows a few https redirects to the configured hosts and
// drops the token on any hop off the API host.
func (h *Handler) planRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" || !h.allowed[req.URL.Host] || req.URL.User != nil {
		return fmt.Errorf("redirect to %s://%s is not allowed", req.URL.Scheme, req.URL.Host)
	}
	if req.URL.Host != h.cfg.Hostname {
		req.Header.Del("Authorization")
	}
	return nil
}

// redact keeps a URL error's operation, host and cause, never its query: a
// redirect target is a signed URL.
func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		host := ""
		if u, perr := url.Parse(ue.URL); perr == nil {
			host = u.Host
		}
		return fmt.Errorf("%s %s: %w", ue.Op, host, redact(ue.Err))
	}
	return err
}

// taskResult is the JSON:API callback body.
type taskResult struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"attributes"`
		Relationships *struct {
			Outcomes struct {
				Data []resultOutcome `json:"data"`
			} `json:"outcomes"`
		} `json:"relationships,omitempty"`
	} `json:"data"`
}

type resultOutcome struct {
	Type       string `json:"type"`
	Attributes struct {
		OutcomeID   string                  `json:"outcome-id"`
		Description string                  `json:"description"`
		Body        string                  `json:"body"`
		Tags        map[string][]outcomeTag `json:"tags"`
	} `json:"attributes"`
}

type outcomeTag struct {
	Label string `json:"label"`
	Level string `json:"level"`
}

// taskResult maps an outcome to the callback: failed for a failed run, and
// for a blocking finding under mandatory enforcement; advisory runs pass
// with their findings as outcomes.
func (h *Handler) taskResult(p *payload, o outcome) taskResult {
	var r taskResult
	r.Data.Type = "task-results"
	status, msg := taskPassed, summary(o.findings)
	switch {
	case o.status == statusFailed:
		status, msg = taskFailed, "ctfkit: "+o.reason
	case o.blocking && p.Enforcement == enforcementMandatory:
		status = taskFailed
	}
	r.Data.Attributes.Status = status
	r.Data.Attributes.Message = clip(msg + "; receipt " + o.status + ", graph controls need a gate verdict, which HCP and TFE runs never carry")
	if !p.Capabilities.Outcomes || len(o.findings) == 0 {
		return r
	}
	r.Data.Relationships = &struct {
		Outcomes struct {
			Data []resultOutcome `json:"data"`
		} `json:"outcomes"`
	}{}
	for i, f := range o.findings {
		if i == maxOutcomes {
			break
		}
		var out resultOutcome
		out.Type = "task-result-outcomes"
		out.Attributes.OutcomeID = fmt.Sprintf("ctfkit-%d-%s", i+1, f.RuleID)
		out.Attributes.Description = clip(f.Message.Text)
		out.Attributes.Body = clip(f.Message.Text)
		level := f.Level
		if f.Suppressed() {
			level = "info"
		}
		out.Attributes.Tags = map[string][]outcomeTag{"Status": {{Label: f.Level, Level: tagLevel(level)}}}
		r.Data.Relationships.Outcomes.Data = append(r.Data.Relationships.Outcomes.Data, out)
	}
	return r
}

func tagLevel(level string) string {
	switch level {
	case ctfkit.LevelError:
		return "error"
	case ctfkit.LevelWarning:
		return "warning"
	}
	return "info"
}

func summary(fs ctfkit.Findings) string {
	var errs, warns, other int
	for _, f := range fs {
		switch {
		case f.Suppressed():
			other++
		case f.Level == ctfkit.LevelError:
			errs++
		case f.Level == ctfkit.LevelWarning:
			warns++
		default:
			other++
		}
	}
	return fmt.Sprintf("ctfkit by compliance.tf (preview): %d error, %d warning and %d other findings", errs, warns, other)
}

func clip(s string) string {
	r := []rune(s)
	if len(r) <= maxMessageRunes {
		return s
	}
	return string(r[:maxMessageRunes-3]) + "..."
}

// post PATCHes the task result to the callback URL with the run's token. No
// redirect is followed.
func (h *Handler) post(ctx context.Context, p *payload, result taskResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, p.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return redact(err)
	}
	req.Header.Set("Content-Type", jsonAPIType)
	req.Header.Set("Authorization", "Bearer "+p.AccessToken)
	resp, err := h.callback.Do(req)
	if err != nil {
		return redact(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCalloutBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
