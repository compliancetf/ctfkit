package verdict

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrContentDigest: a verdict, candidate.json or approval is bound to a
// content digest the verified inputs do not give.
var ErrContentDigest = errors.New("content digest mismatch")

// coverKinds are the exemption kinds a coverable list may hold.
var coverKinds = map[string]bool{"grant": true, "baseline": true, "break_glass": true, "self_service": true}

// ContentDigest is the content_digest (B11) of the verified bundles, as the
// provider's bundle.ContentDigestOf computes it:
//
//	"sha256:" + hex(sha256(JCS({"bundles": [{bundle_id, controls, graph,
//	iam_actions}] sorted by bundle_id, "coverable": {id: [kinds]}})))
//
// controls, graph and iam_actions are the DigestJSON of controls.json,
// graph.json and iam-actions.json ("" when the bundle has no such file).
// coverable lists every control id of every bundle with its sorted
// exemption_coverable kinds, [] when it has none. It is read only from the
// verified bundle bytes (F14): the profile, sidecars, grants, approvals,
// verdicts, baselines and floor_mode are never inputs, so the airgap
// break_glass drop does not apply here.
func ContentDigest(v *Verified) (string, error) {
	if v == nil {
		return "", errors.New("content digest: no verified inputs")
	}
	bundles := make([]any, 0, len(v.Bundles))
	cov := map[string]any{}
	kinds := map[string][]string{} // control id -> its list, for the conflict check
	seen := map[string]bool{}
	for _, b := range v.Bundles {
		if b.Manifest == nil {
			return "", errors.New("content digest: a bundle has no manifest")
		}
	}
	sorted := slices.Clone(v.Bundles)
	slices.SortFunc(sorted, func(a, b VerifiedBundle) int { return strings.Compare(a.Manifest.BundleID, b.Manifest.BundleID) })
	for _, b := range sorted {
		id := b.Manifest.BundleID
		if seen[id] {
			return "", fmt.Errorf("content digest: duplicate bundle_id %s", id)
		}
		seen[id] = true
		entry := map[string]any{"bundle_id": id}
		for _, f := range [][2]string{{ControlsFile, "controls"}, {GraphFile, "graph"}, {IAMActionsFile, "iam_actions"}} {
			name, key := f[0], f[1]
			entry[key] = ""
			body, ok := b.Files[name]
			if !ok {
				continue
			}
			d, err := digestJSON(body)
			if err != nil {
				return "", fmt.Errorf("content digest: bundle %s %s: %w", id, name, err)
			}
			entry[key] = d
		}
		bundles = append(bundles, entry)
		if err := coverable(b.Files[ControlsFile], kinds); err != nil {
			return "", fmt.Errorf("content digest: bundle %s: %w", id, err)
		}
	}
	for id, ks := range kinds {
		list := make([]any, 0, len(ks))
		for _, k := range ks {
			list = append(list, k)
		}
		cov[id] = list
	}
	pre, err := json.Marshal(map[string]any{"bundles": bundles, "coverable": cov})
	if err != nil {
		return "", err
	}
	return jcsDigest(pre)
}

// coverable adds the exemption_coverable list of every control in
// controls.json (a JSON array of controls; nil adds nothing) to kinds. A list
// must hold known kinds, sorted and unique, as the provider's control decoder
// requires; one id with two different lists is control_coverable_conflict.
func coverable(controls []byte, kinds map[string][]string) error {
	if controls == nil {
		return nil
	}
	var cs []struct {
		ID                 string   `json:"id"`
		ExemptionCoverable []string `json:"exemption_coverable"`
	}
	if err := json.Unmarshal(controls, &cs); err != nil {
		return fmt.Errorf("%s: %w", ControlsFile, err)
	}
	if len(cs) == 0 {
		return fmt.Errorf("%s: no controls", ControlsFile) // null or [], the provider's controls_empty
	}
	for _, c := range cs {
		if c.ID == "" {
			return fmt.Errorf("%s: a control has no id", ControlsFile)
		}
		ks := c.ExemptionCoverable
		if ks == nil {
			ks = []string{}
		}
		for i, k := range ks {
			if !coverKinds[k] || i > 0 && ks[i-1] >= k {
				return fmt.Errorf("control %s: exemption_coverable must be sorted unique kinds of grant, baseline, break_glass, self_service", c.ID)
			}
		}
		if prev, ok := kinds[c.ID]; ok && !slices.Equal(prev, ks) {
			return fmt.Errorf("control_coverable_conflict: control %s declares different exemption_coverable lists", c.ID)
		}
		kinds[c.ID] = ks
	}
	return nil
}

// digestJSON is the provider's bundle.DigestJSON: "sha256:" + hex of sha256
// over the JCS form of raw, which must be one I-JSON value.
func digestJSON(raw []byte) (string, error) {
	c, err := checkedJCS(raw, true)
	if err != nil {
		return "", err
	}
	return sha256Digest(c), nil
}

// CheckContentDigest refuses a verdict, candidate.json or approval whose
// content_digest is not the ContentDigest of v.
func CheckContentDigest(v *Verified, bound string) error {
	want, err := ContentDigest(v)
	if err != nil {
		return err
	}
	if bound != want {
		return fmt.Errorf("%w: issued for control content %q, inputs give %s: re-run plan and gate", ErrContentDigest, bound, want)
	}
	return nil
}
