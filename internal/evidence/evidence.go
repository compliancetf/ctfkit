// Package evidence reads the provider's evidence chains (evidence-record-1):
// one JSONL file per provider process, each line linked to the previous one by
// sha256 over the previous line's bytes (LF excluded). A line is its own
// RFC 8785 form, so Verify never canonicalizes; it only checks that each line
// equals its canonical re-encoding.
//
// Verify is a port of the provider's internal/evidence Verify and must keep
// its semantics; schema/testdata/provider-evidence/SOURCE.json records the
// provider commit it matches. VerifySegments stitches the segment files of one
// chain, which the provider leaves to ctfkit. Records are not validated
// against schema/evidence-record-1.schema.json here; cmd/schemacheck does that
// for the goldens.
package evidence

// Kind is the record kind.
type Kind string

// The record kinds of evidence-record-1.
const (
	KindChainStart Kind = "chain_start"
	KindConfigure  Kind = "configure"
	KindEval       Kind = "eval"
	KindChainBreak Kind = "chain_break"
	KindChainEnd   Kind = "chain_end"
)

// Link names a committed line by seq and hash (chain_break.last_good).
type Link struct {
	Hash string `json:"hash"`
	Seq  int64  `json:"seq"`
}

// Run identifies the Terraform run. ClassClaimed is unverified.
type Run struct {
	ClassClaimed *string `json:"class_claimed"`
	ID           string  `json:"id"`
	IDSource     string  `json:"id_source"`
}
