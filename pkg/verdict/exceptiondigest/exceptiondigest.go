// Package exceptiondigest computes the exception digests a verdict lists in
// exceptions[] and instances[].exceptions[] (B8). The gate writes them and the
// terraform provider matches them, so both sides must produce the same
// "sha256:<hex>" string for the same exemption:
//
//   - a signed grant is sha256 of its raw DSSE envelope bytes, as read from
//     the file, never reparsed;
//   - a self-service sidecar entry is sha256 of the RFC 8785 form of
//     {label, workspace, controls, selector, environments, expires}, with
//     controls and environments sorted, so reordering attributes or list
//     members leaves the digest unchanged.
//
// A digest names an exemption; computing one does not validate it. The
// sidecar loader checks ids, scope values, dates and the selector first.
package exceptiondigest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"unicode/utf8"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Grant is the digest of one DSSE grant envelope: sha256 over exactly the
// bytes given, so a whitespace change is a different grant.
func Grant(envelope []byte) string {
	return sum(envelope)
}

// Entry is one self-service sidecar exception block as written. Selector is
// the block's match string verbatim; Controls are the refs as written (ccm
// ids or aliases, unresolved, duplicates kept); Expires is the written
// YYYY-MM-DD date; nil Environments equals an empty list. Reason and ticket
// are not part of the digest.
type Entry struct {
	Label        string
	Workspace    string
	Controls     []string
	Selector     string
	Environments []string
	Expires      string
}

// SelfService is the digest of one sidecar entry. It fails on an empty
// label, workspace, selector, expires or controls list, and on a string that
// is not valid UTF-8, which encoding/json would otherwise replace and so
// collide two different entries.
func SelfService(e Entry) (string, error) {
	if e.Label == "" || e.Workspace == "" || e.Selector == "" || e.Expires == "" || len(e.Controls) == 0 {
		return "", errors.New("exceptiondigest: label, workspace, controls, selector and expires are required")
	}
	controls, envs := sorted(e.Controls), sorted(e.Environments)
	for _, s := range slices.Concat([]string{e.Label, e.Workspace, e.Selector, e.Expires}, controls, envs) {
		if !utf8.ValidString(s) {
			return "", errors.New("exceptiondigest: entry holds invalid UTF-8")
		}
	}
	raw, err := json.Marshal(map[string]any{
		"label": e.Label, "workspace": e.Workspace, "controls": controls,
		"selector": e.Selector, "environments": envs, "expires": e.Expires,
	})
	if err != nil {
		return "", err
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	return sum(canon), nil
}

// sorted is a sorted copy of s, never nil, so the caller's slice is untouched
// and an absent list encodes as [].
func sorted(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out) // byte order; ids and scope values are ASCII, so every sorter agrees
	return out
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
