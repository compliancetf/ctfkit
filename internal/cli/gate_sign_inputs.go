package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/internal/gate"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// Files gate sign and ctfkit apply add to the artifact set.
const (
	artifactVerdict   = "verdict.json"
	artifactResult    = "result.json"
	artifactTombstone = "ctfkit-run.tombstone"
)

// cisBundleID is the bundle the provider always loads from its binary; its
// bundle_digest and content_digest include it, so a verdict matches only
// when --bundle-dir holds the same bundle.
const cisBundleID = "cis-aws"

// errSigned is readArtifactSet refusing a candidate gate sign signed before.
var errSigned = errors.New("already holds a verdict; a candidate is signed once")

// readArtifactSet reads the candidate artifact set: a directory of the
// runner's uid with no mode bits outside 0700 holding exactly the files
// candidate.json lists plus candidate.json, each a regular file with no mode
// bits outside 0600 whose raw digest candidate.json names. signed (ctfkit
// apply, verdict verify) requires verdict.json beside them, else (gate sign)
// there must be no verdict yet. Custody files ctfkit apply writes are left
// out of the exact list and returned by name; gate sign refuses a set
// holding any. A tombstoned set returns errTombstoned before anything is
// read. It returns the files, the candidate and the custody files present.
func readArtifactSet(dir string, signed bool) (map[string][]byte, *candidate, []string, error) {
	return readSetMode(dir, signed, signed)
}

// readSetMode is readArtifactSet with its two rules apart: signed allows a
// verdict and custody files, needVerdict requires the verdict. The reaper
// reads with signed and no verdict needed, so it still finds an unsigned set
// that an interrupted reap left custody files in.
func readSetMode(dir string, signed, needVerdict bool) (map[string][]byte, *candidate, []string, error) {
	st, err := os.Lstat(dir)
	switch {
	case err != nil:
		return nil, nil, nil, err
	case !st.IsDir():
		return nil, nil, nil, errors.New("not a directory")
	case st.Mode().Perm()&^0o700 != 0 || !ownedByUs(st):
		return nil, nil, nil, errors.New("must be a 0700 directory owned by this user")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	files := map[string][]byte{}
	var custody []string
	for _, e := range entries {
		switch {
		case e.Name() == artifactTombstone:
			return nil, nil, nil, errTombstoned
		case e.Name() == artifactVerdict && !signed:
			return nil, nil, nil, errSigned
		}
		p := filepath.Join(dir, e.Name())
		fi, ferr := os.Lstat(p)
		if ferr != nil {
			return nil, nil, nil, ferr
		}
		if isCustody(e.Name()) {
			if !signed {
				return nil, nil, nil, fmt.Errorf("holds %s: ctfkit apply ran on it", e.Name())
			}
			if err = checkCustodyMode(e.Name(), fi); err != nil {
				return nil, nil, nil, err
			}
			custody = append(custody, e.Name())
			continue
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&^0o600 != 0 || !ownedByUs(fi) {
			return nil, nil, nil, fmt.Errorf("%s: must be a 0600 regular file owned by this user", e.Name())
		}
		if files[e.Name()], err = readCapped(p, maxPlanBytes); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	raw, ok := files[artifactCandidate]
	if !ok {
		return nil, nil, nil, errors.New("no candidate.json: not a complete candidate")
	}
	cand, err := parseCandidate(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	want := slices.Sorted(maps.Keys(cand.Artifacts))
	if _, ok = files[artifactVerdict]; needVerdict && !ok {
		return nil, nil, nil, errors.New("holds no verdict.json: run gate sign first")
	}
	got := slices.DeleteFunc(slices.Sorted(maps.Keys(files)), func(n string) bool { return n == artifactCandidate || (signed && n == artifactVerdict) })
	if !slices.Equal(want, got) || !slices.Equal(want, []string{artifactRunKey, artifactFindings, artifactPlanfile, artifactSchema}) {
		return nil, nil, nil, fmt.Errorf("holds %q, candidate.json lists %q", got, want)
	}
	for name, d := range cand.Artifacts {
		if rawDigest(files[name]) != d {
			return nil, nil, nil, fmt.Errorf("%s does not match its digest in candidate.json", name)
		}
	}
	return files, cand, custody, nil
}

// parseCandidate decodes candidate.json strictly: JCS bytes, no unknown
// member, format compliancetf.candidate/v1 and kind plan only.
func parseCandidate(raw []byte) (*candidate, error) {
	canon, err := jcs.Transform(raw)
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, errors.New("candidate.json is not canonical JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c candidate
	if err = dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("candidate.json: %w", err)
	}
	switch {
	case c.Format != candidateFormat:
		return nil, fmt.Errorf("candidate.json format %q: gate sign accepts only %s", c.Format, candidateFormat)
	case c.Kind != "plan":
		return nil, fmt.Errorf("candidate.json kind %q: only a plan candidate is signed", c.Kind)
	}
	return &c, nil
}

// signSettings are the signed profile members gate sign reads; VerifyInputs
// verified the profile and left them raw.
type signSettings struct {
	scope struct {
		Environment string `json:"environment"`
		Workspace   string `json:"workspace"`
	}
	verdict struct {
		PublicKeys []struct {
			KID       string    `json:"kid"`
			Alg       string    `json:"alg"`
			Use       string    `json:"use"`
			SPKIB64   string    `json:"spki_b64"`
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
		} `json:"public_keys"`
		MaxTTL string `json:"max_ttl"`
	}
	modeFloor     gate.ModeFloor
	controlFloors map[string]string
	exceptions    struct {
		ForbidControls []string `json:"forbid_controls"`
	}
	keys []verdict.PublicKey
	ttl  time.Duration
}

func parseSignSettings(p *verdict.Profile) (*signSettings, error) {
	s := &signSettings{}
	for _, m := range []struct {
		name string
		raw  json.RawMessage
		v    any
	}{{"scope", p.Scope, &s.scope}, {"verdict", p.Verdict, &s.verdict}, {"mode_floor", p.ModeFloor, &s.modeFloor},
		{"control_floors", p.ControlFloors, &s.controlFloors}, {"exceptions", p.Exceptions, &s.exceptions}} {
		if len(m.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(m.raw, m.v); err != nil {
			return nil, fmt.Errorf("profile %s: %w", m.name, err)
		}
	}
	s.ttl = 24 * time.Hour
	if s.verdict.MaxTTL != "" {
		d, err := time.ParseDuration(s.verdict.MaxTTL)
		if err != nil || d <= 0 || d > 72*time.Hour {
			return nil, fmt.Errorf("profile verdict.max_ttl %q: want a duration up to 72h", s.verdict.MaxTTL)
		}
		s.ttl = d
	}
	for _, k := range s.verdict.PublicKeys {
		if k.Use != "verdict" || k.Alg != verdict.AlgES256 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.SPKIB64)
		if err != nil {
			return nil, fmt.Errorf("profile verdict key %s: %w", k.KID, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		ec, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok || verdict.KeyID(der) != k.KID {
			return nil, fmt.Errorf("profile verdict key %s: not an ES256 key with that kid", k.KID)
		}
		if k.NotAfter.After(p.ExpiresAt) { // the provider clamps a key to the profile's lifetime
			k.NotAfter = p.ExpiresAt
		}
		s.keys = append(s.keys, verdict.PublicKey{Kid: k.KID, Key: ec, Use: k.Use, NotBefore: k.NotBefore, NotAfter: k.NotAfter})
	}
	if len(s.keys) == 0 {
		return nil, errors.New("profile lists no ES256 verdict key: nothing could verify a verdict")
	}
	return s, nil
}

// checkScope refuses a workspace or environment the signed profile does
// not allow: a scope dimension the profile fixes must be equal, and when
// mode_floor names environments the environment must be one of them.
func (s *signSettings) checkScope(workspace, environment string) error {
	switch {
	case s.scope.Workspace != "" && s.scope.Workspace != workspace:
		return fmt.Errorf("workspace %q is not the profile's workspace %q", workspace, s.scope.Workspace)
	case s.scope.Environment != "" && s.scope.Environment != environment:
		return fmt.Errorf("environment %q is not the profile's environment %q", environment, s.scope.Environment)
	case len(s.modeFloor.Environments) > 0 && s.modeFloor.Environments[environment] == "":
		return fmt.Errorf("environment %q is not an environment of the profile", environment)
	}
	return nil
}

// modeTable is the provider's run mode with the profile (gate.ModeTable).
func (s *signSettings) modeTable() resolve.ModeTable {
	return gate.ModeTable(s.modeFloor, s.controlFloors, s.scope.Environment)
}

// coverable is the effective coverable list of every control: the signed
// exemption_coverable of the bundle, emptied for a profile forbid_controls
// id, break_glass dropped unless floor_mode is online (the provider's
// Coverability; a coverable list the profile adds is never read, F14).
func (s *signSettings) coverable(controls []gate.Control, floorMode string) func(string) []string {
	m := map[string][]string{}
	for _, c := range controls {
		kinds := slices.Clone(c.ExemptionCoverable)
		if slices.ContainsFunc(s.exceptions.ForbidControls, func(f string) bool { return strings.EqualFold(f, c.ID) }) {
			kinds = nil
		}
		if floorMode != verdict.FloorOnline {
			kinds = slices.DeleteFunc(kinds, func(k string) bool { return k == resolve.KindBreakGlass })
		}
		m[c.ID] = kinds
	}
	return func(id string) []string { return m[id] }
}

// bundleControls decodes the controls of every verified bundle and refuses
// a bundle set without the provider's embedded CIS bundle.
func bundleControls(v *verdict.Verified) ([]gate.Control, error) {
	var out []gate.Control
	cis := false
	for _, b := range v.Bundles {
		cis = cis || b.Manifest.BundleID == cisBundleID
		cs, err := gate.ParseControls(b.Files[verdict.ControlsFile])
		if err != nil {
			return nil, fmt.Errorf("bundle %s: %w", b.Manifest.BundleID, err)
		}
		out = append(out, cs...)
	}
	if !cis {
		return nil, fmt.Errorf("--bundle-dir holds no %s bundle: the provider always loads its embedded CIS bundle, "+
			"so its bundle and content digests would differ; place the CIS bundle of the provider release in --bundle-dir/%s", cisBundleID, cisBundleID)
	}
	return out, nil
}

// providerVersions are the exact versions the dependency lock file pins
// for the compliance.tf provider and the hashicorp/aws it wraps; the
// provider refuses a verdict whose versions differ from the running ones.
func providerVersions(lock *ctfkit.Lockfile) (map[string]string, error) {
	out := map[string]string{}
	if lock != nil {
		for _, p := range lock.Providers {
			for _, name := range []string{"compliancetf/aws", "hashicorp/aws"} {
				if strings.HasSuffix(strings.ToLower(p.Source), "/"+name) {
					out[name] = strings.TrimPrefix(p.Version, "v")
				}
			}
		}
	}
	if out["compliancetf/aws"] == "" || out["hashicorp/aws"] == "" {
		return nil, errors.New("the dependency lock file must pin compliancetf/aws and hashicorp/aws: the verdict binds both versions")
	}
	return out, nil
}
