package verdict

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Break-glass document formats. The app signs both with a key the profile
// lists in break_glass.receipt_keys (use "receipt"); that key also signs each
// approval statement (ApprovalStatement).
const (
	OverrideFormat = "compliancetf.override/v1"
	ReceiptFormat  = "compliancetf.consume-receipt/v1"
)

// MaxOverrideTTL bounds an override's expires_at - issued_at.
const MaxOverrideTTL = 24 * time.Hour

// UseReceipt is the key use of break_glass.receipt_keys.
const UseReceipt = "receipt"

// Override is a compliancetf.override/v1 document (schema override-1): a
// break-glass request the app signed with its two approvals embedded.
type Override struct {
	Format                   string     `json:"format"`
	OverrideID               string     `json:"override_id"`
	OrgID                    string     `json:"org_id"`
	Workspace                string     `json:"workspace"`
	Environment              string     `json:"environment"`
	Requester                string     `json:"requester"`
	PlanDigest               string     `json:"plan_digest"`
	ContentDigest            string     `json:"content_digest"`
	FloorEpoch               string     `json:"floor_epoch"`
	InstanceKeys             []string   `json:"instance_keys"`
	Controls                 []string   `json:"controls"`
	Approvals                []Approval `json:"approvals"`
	Reason                   string     `json:"reason"`
	Ticket                   string     `json:"ticket"`
	IssuedAt                 string     `json:"issued_at"`
	ExpiresAt                string     `json:"expires_at"`
	PredecessorReceiptDigest string     `json:"predecessor_receipt_digest,omitempty"`
	Signature                Signature  `json:"signature"`
}

// Approval is one signed approval of an override. Its signature covers
// ApprovalStatement, not the approval object.
type Approval struct {
	Approver   string    `json:"approver"`
	Role       string    `json:"role"`
	ApprovedAt string    `json:"approved_at"`
	ExpiresAt  string    `json:"expires_at"`
	Signature  Signature `json:"signature"`
}

// Receipt is a compliancetf.consume-receipt/v1 document (schema
// consume-receipt-1), member for member the provider's internal/breakglass
// Receipt.
type Receipt struct {
	Format                   string    `json:"format"`
	OverrideID               string    `json:"override_id"`
	OverrideDigest           string    `json:"override_digest"`
	OrgID                    string    `json:"org_id"`
	RunID                    string    `json:"run_id"`
	RequestDigest            string    `json:"request_digest"`
	Controls                 []string  `json:"controls"`
	InstanceKeys             []string  `json:"instance_keys"`
	PlanDigest               string    `json:"plan_digest"`
	ConsumedAt               string    `json:"consumed_at"`
	ExpiresAt                string    `json:"expires_at"`
	PredecessorReceiptDigest string    `json:"predecessor_receipt_digest,omitempty"`
	Signature                Signature `json:"signature"`
}

// RequestScope is what a break-glass request_digest (B9) binds. Controls and
// InstanceKeys (action keys: instance_key, or delete_key for a destroy half)
// are taken as given; RequestDigest sorts copies and keeps duplicates.
type RequestScope struct {
	OrgID         string   `json:"org_id"`
	Workspace     string   `json:"workspace"`
	Environment   string   `json:"environment"`
	PlanDigest    string   `json:"plan_digest"`
	ContentDigest string   `json:"content_digest"`
	FloorEpoch    string   `json:"floor_epoch"`
	OverrideID    string   `json:"override_id"`
	Controls      []string `json:"controls"`
	InstanceKeys  []string `json:"instance_keys"`
}

// Break-glass parse errors.
var (
	ErrInvalidOverride = errors.New("not a " + OverrideFormat + " document")
	ErrInvalidReceipt  = errors.New("not a " + ReceiptFormat + " document")
)

// reToken is an override id or control id: the provider's evidence token.
var reToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// RequestDigest is B9: "sha256:" + hex of sha256 over JCS of s with Controls
// and InstanceKeys sorted bytewise (not deduplicated; a nil list is null). It
// equals the provider's breakglass.RequestDigest.
func RequestDigest(s RequestScope) (string, error) {
	s.Controls, s.InstanceKeys = sortedCopy(s.Controls), sortedCopy(s.InstanceKeys)
	b, err := json.Marshal(s)
	if err == nil {
		b, err = jcs.Transform(b)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Scope is the request scope o was approved for.
func (o *Override) Scope() RequestScope {
	return RequestScope{OrgID: o.OrgID, Workspace: o.Workspace, Environment: o.Environment, PlanDigest: o.PlanDigest,
		ContentDigest: o.ContentDigest, FloorEpoch: o.FloorEpoch, OverrideID: o.OverrideID,
		Controls: o.Controls, InstanceKeys: o.InstanceKeys}
}

// Scope is the request scope the provider recomputes for r embedded in d:
// org_id, workspace, environment, plan_digest, content_digest and
// floor_epoch from the verdict, override_id, controls and instance_keys from
// the receipt.
func (r *Receipt) Scope(d *Document) RequestScope {
	return RequestScope{OrgID: d.OrgID, Workspace: d.Workspace, Environment: d.Environment, PlanDigest: d.PlanDigest,
		ContentDigest: d.ContentDigest, FloorEpoch: d.FloorEpoch, OverrideID: r.OverrideID,
		Controls: r.Controls, InstanceKeys: r.InstanceKeys}
}

// ApprovalStatement is the bytes approvals[i]'s signature covers: JCS of
// {override_id, org_id, workspace, environment, plan_digest, content_digest,
// floor_epoch, instance_keys (sorted), controls (sorted)} of o and {approver,
// role, expires_at} of the approval. Check it with Verify(statement,
// o.Approvals[i].Signature, keys, revoked, UseReceipt, now).
func ApprovalStatement(o *Override, i int) ([]byte, error) {
	if o == nil || i < 0 || i >= len(o.Approvals) {
		return nil, ErrInvalidOverride
	}
	a := o.Approvals[i]
	b, err := json.Marshal(map[string]any{
		"override_id": o.OverrideID, "org_id": o.OrgID, "workspace": o.Workspace, "environment": o.Environment,
		"plan_digest": o.PlanDigest, "content_digest": o.ContentDigest, "floor_epoch": o.FloorEpoch,
		"instance_keys": sortedCopy(o.InstanceKeys), "controls": sortedCopy(o.Controls),
		"approver": a.Approver, "role": a.Role, "expires_at": a.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// Digest is "sha256:" + hex of sha256 over JCS of the whole document,
// signature included: a receipt's digest (verdict instances[].break_glass)
// and an override's override_digest. raw must be strict (see SignedBytes).
func Digest(raw []byte) (string, error) {
	canon, err := canonical(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ParseOverride decodes an override strictly, as Parse does, then checks its
// shape and the rules the document alone decides: override_id and controls
// are tokens, digests are "sha256:" + 64 lowercase hex, lists are non-empty
// and duplicate-free, signatures have the schema's shape, times are RFC
// 3339 UTC, expires_at is after issued_at
// by at most MaxOverrideTTL, and exactly two approvals by distinct approvers,
// neither the requester, each expiring no later than the override. It checks
// no signature and no binding to a candidate.
func ParseOverride(raw []byte) (*Override, error) {
	var o Override
	if !parseStrict(raw, &o) || o.Format != OverrideFormat || !overrideOK(&o) {
		return nil, ErrInvalidOverride
	}
	return &o, nil
}

func overrideOK(o *Override) bool {
	issued, err1 := parseUTC(o.IssuedAt)
	expires, err2 := parseUTC(o.ExpiresAt)
	if err1 != nil || err2 != nil || !expires.After(issued) || expires.Sub(issued) > MaxOverrideTTL ||
		!reToken.MatchString(o.OverrideID) || slices.Contains([]string{o.OrgID, o.Workspace, o.Environment, o.Requester, o.FloorEpoch}, "") ||
		!reDigest.MatchString(o.PlanDigest) || !reDigest.MatchString(o.ContentDigest) || !sigOK(o.Signature) ||
		o.PredecessorReceiptDigest != "" && !reDigest.MatchString(o.PredecessorReceiptDigest) ||
		!list(o.Controls, reToken) || !list(o.InstanceKeys, reDigest) || len(o.Approvals) != 2 ||
		o.Approvals[0].Approver == o.Approvals[1].Approver {
		return false
	}
	for _, a := range o.Approvals {
		_, err1 := parseUTC(a.ApprovedAt)
		aexp, err2 := parseUTC(a.ExpiresAt)
		if err1 != nil || err2 != nil || aexp.After(expires) || !sigOK(a.Signature) || a.Approver == "" || a.Role == "" || a.Approver == o.Requester {
			return false
		}
	}
	return true
}

// ParseReceipt decodes a receipt strictly, as Parse does, then checks the
// provider's member shapes (override_id and controls are tokens, org_id and
// run_id non-empty, digests "sha256:" + 64 lowercase hex, non-empty
// duplicate-free lists) and, stricter than the provider, the signature's
// schema shape and consumed_at and expires_at in the schema's RFC 3339 UTC
// grammar. It accepts no receipt the
// provider's parse refuses. It checks no signature and no binding to a
// verdict.
func ParseReceipt(raw []byte) (*Receipt, error) {
	var r Receipt
	if !parseStrict(raw, &r) || r.Format != ReceiptFormat || !receiptOK(&r) {
		return nil, ErrInvalidReceipt
	}
	return &r, nil
}

func receiptOK(r *Receipt) bool {
	_, err1 := parseUTC(r.ConsumedAt)
	_, err2 := parseUTC(r.ExpiresAt)
	return err1 == nil && err2 == nil && reToken.MatchString(r.OverrideID) && r.OrgID != "" && r.RunID != "" &&
		reDigest.MatchString(r.OverrideDigest) && reDigest.MatchString(r.RequestDigest) && reDigest.MatchString(r.PlanDigest) &&
		(r.PredecessorReceiptDigest == "" || reDigest.MatchString(r.PredecessorReceiptDigest)) &&
		list(r.Controls, reToken) && list(r.InstanceKeys, reDigest) && sigOK(r.Signature)
}

// reSigValue is base64url without padding, as the schemas state.
var reSigValue = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// sigOK checks a signature's schema shape only; Verify checks the signature.
func sigOK(s Signature) bool {
	return reDigest.MatchString(s.Kid) && s.Alg == AlgES256 && reSigValue.MatchString(s.Value)
}

// list reports a non-empty, duplicate-free list of values matching re.
func list(s []string, re *regexp.Regexp) bool {
	c := sortedCopy(s)
	for i, v := range c {
		if !re.MatchString(v) || i > 0 && c[i-1] == v {
			return false
		}
	}
	return len(c) > 0
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// reTime is the schemas' RFC 3339 UTC grammar. time.Parse alone also takes
// a one-digit hour or a comma before the fraction (so does the provider's
// check, which this is stricter than).
var reTime = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?Z$`)

func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !reTime.MatchString(s) {
		return time.Time{}, errNotStrict
	}
	return t, nil
}
