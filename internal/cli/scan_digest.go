package cli

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// findingsDigestAlgorithm names what findingsDigest hashes. A change to the
// entry fields, their normalization or their order is a new version of this
// name, never a new value under it, so a later job comparing two digests
// knows they were computed the same way.
const findingsDigestAlgorithm = "jcs-sha256/v1"

// digestEntry is one finding as the digest sees it: what the scan found and
// where, and nothing about the run that found it. Left out on purpose: the
// ctf.evidence run id and commit, the waiver's TTL, which counts down with the
// clock, the tool and catalog versions, and the catalog-derived control ids,
// frameworks and remediation, which the binding records beside the digest.
type digestEntry struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Kind       string            `json:"kind"`
	Message    string            `json:"message"`
	Locations  []ctfkit.Location `json:"locations"`
	Suppressed bool              `json:"suppressed"`

	uri   string // first physical location, the sort key
	line  int
	canon []byte // the entry's RFC 8785 form, the last tie-breaker
}

// findingsDigest is "sha256:<hex>" over the RFC 8785 form of the findings'
// digest entries, sorted by rule id, first location uri and line, message,
// then canonical bytes. The input order does not matter and URIs are POSIX
// separated, so a re-scan of the same plan on another runner, another OS or
// at another time gives the same value.
func findingsDigest(fs ctfkit.Findings) (string, error) {
	entries := make([]digestEntry, 0, len(fs))
	for _, f := range fs {
		e := digestEntry{
			RuleID: f.RuleID, Level: f.Level, Kind: f.Kind, Message: f.Message.Text,
			Locations: make([]ctfkit.Location, 0, len(f.Locations)), Suppressed: f.Suppressed(),
		}
		for _, l := range f.Locations {
			if p := l.PhysicalLocation; p != nil {
				phys := *p
				phys.ArtifactLocation.URI = strings.ReplaceAll(p.ArtifactLocation.URI, `\`, "/")
				l.PhysicalLocation = &phys // a copy: the caller's finding is not touched
				if e.uri == "" {
					e.uri = phys.ArtifactLocation.URI
					if phys.Region != nil {
						e.line = phys.Region.StartLine
					}
				}
			}
			e.Locations = append(e.Locations, l)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return "", fmt.Errorf("findings digest: %w", err)
		}
		if e.canon, err = jcs.Transform(raw); err != nil {
			return "", fmt.Errorf("findings digest: %w", err)
		}
		entries = append(entries, e)
	}

	slices.SortFunc(entries, func(a, b digestEntry) int {
		return cmp.Or(cmp.Compare(a.RuleID, b.RuleID), cmp.Compare(a.uri, b.uri),
			cmp.Compare(a.line, b.line), cmp.Compare(a.Message, b.Message), bytes.Compare(a.canon, b.canon))
	})

	// Each entry is already canonical, so the array of them is too.
	var doc bytes.Buffer
	doc.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			doc.WriteByte(',')
		}
		doc.Write(e.canon)
	}
	doc.WriteByte(']')

	sum := sha256.Sum256(doc.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
