package verdict

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Baseline formats (schema baseline-1) and the approver role.
const (
	BaselineFormat  = "compliancetf.baseline/v1"
	StatementFormat = "compliancetf.baseline-approval/v1"
	RoleApprover    = "baseline_approver"
)

// Baseline is the customer-signed grandfather baseline. Every value is a
// string, array or object. The json tags are the provider's
// (internal/baseline Document): ParseBaseline refuses a document that does
// not re-encode to its own canonical bytes.
type Baseline struct {
	Format        string          `json:"format"`
	OrgID         string          `json:"org_id"`
	IssuedAt      string          `json:"issued_at"`
	ContentDigest string          `json:"content_digest"`
	Entries       []BaselineEntry `json:"entries"`
	Signature     Signature       `json:"signature"`
}

// BaselineEntry grandfathers one (instance, control). Identity is the
// plaintext identity object (identity_kind "identity") or {"id": <id>}
// (identity_kind "id").
type BaselineEntry struct {
	Workspace             string            `json:"workspace"`
	Scope                 BaselineScope     `json:"scope"`
	Type                  string            `json:"type"`
	IdentityKind          string            `json:"identity_kind"`
	Identity              map[string]string `json:"identity"`
	Address               string            `json:"address"`
	Control               string            `json:"control"`
	ControlMajor          string            `json:"control_major"`
	ControlManifestDigest string            `json:"control_manifest_digest"`
	ReadDigest            string            `json:"read_digest"`
	ApproverStatement     ApproverStatement `json:"approver_statement"`
	Approver              string            `json:"approver"`
	Expires               string            `json:"expires"`
	Ticket                string            `json:"ticket"`
}

// BaselineScope is the cloud scope of an entry.
type BaselineScope struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

// ApproverStatement is the app-signed baseline_approver statement, signed
// with a compliance.tf receipt key of the profile.
type ApproverStatement struct {
	Format        string        `json:"format"`
	OrgID         string        `json:"org_id"`
	Role          string        `json:"role"`
	Subject       string        `json:"subject"`
	Workspace     string        `json:"workspace"`
	Scope         BaselineScope `json:"scope"`
	RunID         string        `json:"run_id"`
	PlanDigest    string        `json:"plan_digest"`
	ContentDigest string        `json:"content_digest"`
	IssuedAt      string        `json:"issued_at"`
	Signature     Signature     `json:"signature"`
}

// ErrInvalidBaseline is any document ParseBaseline refuses.
var ErrInvalidBaseline = errors.New("not a compliancetf.baseline/v1 document")

// ParseBaseline decodes a baseline with the strict rules of Parse and checks
// its format. It checks the shape only: signatures (Verify, use baseline for
// the document, receipt for each approver_statement over its SignedBytes),
// expiry and the approver bindings are the caller's.
func ParseBaseline(raw []byte) (*Baseline, error) {
	var doc Baseline
	if !parseStrict(raw, &doc) || doc.Format != BaselineFormat {
		return nil, ErrInvalidBaseline
	}
	return &doc, nil
}

// EntryDigest is the digest a verdict lists for a baseline entry:
// "sha256:" + hex of sha256 over the JCS form of the entry.
func EntryDigest(e BaselineEntry) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return jcsDigest(b)
}

// EntryIdentity is the identity a baseline entry binds for an instance whose
// prior identity kind and tree the instance key adapters chose (tfjson,
// tfvalue: identity object over a non-empty id). Kind identity: the object
// without its null members, every other member a string, at least one
// member. Kind id: {"id": <non-empty string>}. Any other kind or shape is an
// error, and no entry can be written for the instance. The provider's
// matcher (internal/baseline instanceIdentity) applies the same rule; for
// kind id it also requires the planned state to keep the id, which a
// matcher must check, since only the prior is passed here.
func EntryIdentity(kind string, prior any) (map[string]string, error) {
	m, ok := prior.(map[string]any)
	if !ok || kind != "identity" && kind != "id" {
		return nil, fmt.Errorf("no baseline identity for prior identity kind %q", kind)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, isStr := v.(string)
		switch {
		case v == nil && kind == "identity":
			continue
		case !isStr || kind == "id" && (k != "id" || s == ""):
			return nil, fmt.Errorf("prior identity member %q is not a usable string", k)
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, errors.New("prior identity is empty")
	}
	return out, nil
}

// ControlManifestDigest is an entry's control_manifest_digest: "sha256:" +
// hex of sha256 over the JCS form of one bundle 2.0 control as the provider
// loads it (internal/bundle Control): members it omits when empty are
// dropped and a missing exemption_coverable becomes []. raw is one control
// object; null, a duplicate member, a member name outside [a-z0-9_]+ or an
// unknown member is an error. It does not validate the control otherwise.
func ControlManifestDigest(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", errors.New("control is not valid UTF-8")
	}
	if err := scanControl(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return "", err
	}
	var c manifestControl
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return "", fmt.Errorf("control: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", errors.New("control: trailing data")
	}
	if c.ExemptionCoverable == nil {
		c.ExemptionCoverable = []string{}
	}
	b, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	return jcsDigest(b)
}

// manifestControl mirrors the provider's bundle.Control json tags.
type manifestControl struct {
	ID                 string              `json:"id"`
	Version            string              `json:"version"`
	Kind               string              `json:"kind"`
	ResourceType       string              `json:"resource_type"`
	Reads              []string            `json:"reads,omitempty"`
	PresenceMode       string              `json:"presence_mode,omitempty"`
	On                 []string            `json:"on,omitempty"`
	Expr               *string             `json:"expr,omitempty"`
	Graph              *manifestGraph      `json:"graph,omitempty"`
	Action             string              `json:"action"`
	Severity           string              `json:"severity"`
	Message            string              `json:"message"`
	Fix                string              `json:"fix,omitempty"`
	FrameworkRefs      []string            `json:"framework_refs,omitempty"`
	ToolRefs           map[string][]string `json:"tool_refs,omitempty"`
	ExemptionCoverable []string            `json:"exemption_coverable"`
}

type manifestGraph struct {
	Rule          string   `json:"rule"`
	CompanionType string   `json:"companion_type"`
	LinkAttr      string   `json:"link_attr"`
	TargetAttrs   []string `json:"target_attrs"`
	CompanionExpr *string  `json:"companion_expr,omitempty"`
}

var reMember = regexp.MustCompile(`^[a-z0-9_]+$`)

// scanControl is the provider's scanStrict: no null, no duplicate member and
// member names in [a-z0-9_]+ at any depth, for an object at the top.
func scanControl(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	switch {
	case err != nil:
		return fmt.Errorf("control: %w", err)
	case depth == 0 && tok != json.Delim('{'):
		return errors.New("control is not an object")
	case depth > maxDepth:
		return errors.New("control nested too deep")
	case tok == nil:
		return errors.New("control holds null")
	case tok == json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			k, kerr := dec.Token()
			name, _ := k.(string)
			if kerr != nil || !reMember.MatchString(name) || seen[name] {
				return fmt.Errorf("control member %q is a duplicate or not [a-z0-9_]+", name)
			}
			seen[name] = true
			if serr := scanControl(dec, depth+1); serr != nil {
				return serr
			}
		}
	case tok == json.Delim('['):
		for dec.More() {
			if serr := scanControl(dec, depth+1); serr != nil {
				return serr
			}
		}
	default:
		return nil
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// jcsDigest is "sha256:" + hex of sha256 over the JCS form of b.
func jcsDigest(b []byte) (string, error) {
	c, err := jcs.Transform(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
