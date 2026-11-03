// Package verdict is the contract that ctfkit and the compliance.tf terraform
// provider share for the signed verdict compliancetf.verdict/v1 (schema
// verdict-1): the document types, the signed bytes, the ES256 signature check,
// the key id and the bundle set digest, plus the break-glass override and
// consume receipt it carries (breakglass.go). Both sides must compute every
// one of them byte for byte alike; testdata/sig and testdata/breakglass hold
// the vectors that pin them.
package verdict

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Format is the verdict document format.
const Format = "compliancetf.verdict/v1"

// Document is a verdict. Every value is a string, array or object, so its
// signed bytes never meet the JCS number rules. The json tags and omit rules
// are part of the format: Parse rejects a document that does not re-encode to
// its own canonical bytes.
type Document struct {
	Format             string            `json:"format"`
	OrgID              string            `json:"org_id"`
	Workspace          string            `json:"workspace"`
	Environment        string            `json:"environment"`
	RunID              string            `json:"run_id"`
	Caller             json.RawMessage   `json:"caller"`
	PlanDigest         string            `json:"plan_digest"`
	Provenance         json.RawMessage   `json:"provenance"`
	PlanFormatVersion  string            `json:"plan_format_version"`
	ProfileDigest      string            `json:"profile_digest"`
	BundleDigest       string            `json:"bundle_digest"`
	ContentDigest      string            `json:"content_digest"`
	FloorEpoch         string            `json:"floor_epoch"`
	ProviderVersions   map[string]string `json:"provider_versions"`
	TerraformVersion   string            `json:"terraform_version"`
	Nonce              string            `json:"nonce"`
	IssuedAt           string            `json:"issued_at"`
	ExpiresAt          string            `json:"expires_at"`
	InstanceKeyCheck   string            `json:"instance_key_check"`
	Instances          []Instance        `json:"instances"`
	Exceptions         []ExceptionRef    `json:"exceptions"`
	Baselines          []BaselineRef     `json:"baselines"`
	BreakGlassReceipts []json.RawMessage `json:"break_glass_receipts"`
	Signature          Signature         `json:"signature"`
}

// Instance is one verdict entry, one per managed resource change. The
// omitempty members are optional; delete_decisions is present exactly on
// delete and replace entries.
type Instance struct {
	Address           string         `json:"address"`
	Deposed           string         `json:"deposed,omitempty"`
	Type              string         `json:"type"`
	Action            string         `json:"action"`
	PreviousAddress   string         `json:"previous_address,omitempty"`
	InstanceKey       string         `json:"instance_key,omitempty"`
	DeleteKey         string         `json:"delete_key,omitempty"`
	PriorIdentityKind string         `json:"prior_identity_kind"`
	Refreshed         string         `json:"refreshed"`
	UnknownPaths      [][]string     `json:"unknown_paths"`
	Decisions         []Decision     `json:"decisions"`
	DeleteDecisions   []Decision     `json:"delete_decisions,omitzero"`
	NotEvaluable      []NotEvaluable `json:"not_evaluable"`
	Exceptions        []string       `json:"exceptions"`
	Baselines         []string       `json:"baselines"`
	BreakGlass        []string       `json:"break_glass"`
}

// Decision is the gate's decision for one (control, version).
type Decision struct {
	Control string `json:"control"`
	Version string `json:"version"`
	Result  string `json:"result"`
	Action  string `json:"action"`
}

// NotEvaluable names why a control could not be decided at plan.
type NotEvaluable struct {
	Control string `json:"control"`
	Reason  string `json:"reason"`
}

// ExceptionRef is an exception the gate applied.
type ExceptionRef struct {
	Digest  string `json:"digest"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
}

// BaselineRef is a baseline entry the gate matched.
type BaselineRef struct {
	Digest string `json:"digest"`
}

// Signature is {kid, alg, value}; value is base64url (no padding) of the
// ASN.1 DER signature.
type Signature struct {
	Kid   string `json:"kid"`
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// ErrInvalidDocument is any document Parse refuses.
var ErrInvalidDocument = errors.New("not a compliancetf.verdict/v1 document")

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Parse decodes a verdict strictly: the checks of SignedBytes, then the typed
// document must re-encode to the same canonical bytes (no unknown, missing or
// case-variant member, no empty optional member), format must be Format and
// every baselines digest must be "sha256:" + 64 lowercase hex.
// Call it before Verify; Verify checks only the signature.
func Parse(raw []byte) (*Document, error) {
	var doc Document
	if !parseStrict(raw, &doc) || doc.Format != Format {
		return nil, ErrInvalidDocument
	}
	for _, b := range doc.Baselines { // the provider's parse checks these too
		if !reDigest.MatchString(b.Digest) {
			return nil, ErrInvalidDocument
		}
	}
	return &doc, nil
}

// parseStrict decodes raw into doc after the checks of SignedBytes and
// reports whether doc re-encodes to the same canonical bytes.
func parseStrict(raw []byte, doc any) bool {
	canon, err := canonical(raw)
	if err != nil || json.Unmarshal(canon, doc) != nil {
		return false
	}
	re, err := json.Marshal(doc)
	if err == nil {
		re, err = jcs.Transform(re)
	}
	return err == nil && bytes.Equal(re, canon)
}
