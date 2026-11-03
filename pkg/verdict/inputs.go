package verdict

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// VerifyInputs checks every signed input of a gate run before anything is
// evaluated or signed, in the order the provider's Configure checks the
// same files (internal/lifecycle/configure.go): bundle manifests and their
// files, the merged revocations, the profile signature, the floor statement,
// the profile expiry and floor, the bundle minimums, then each bundle's org,
// revocation and expiry. ctfkit runs stateless, so the provider's persisted
// floor high-water, release floor and wrapper version checks are left to the
// provider, which repeats them at Configure. min_wrapper_version is only
// parsed here; the provider orders it by the version parity scheme (base
// X.Y.Z first, then beta.N < release < compliancetf.N), and
// testdata/wrapper_order.json is a byte-identical copy of its order vectors.

// Bundle manifest files and limits (provider internal/bundle/archive.go).
const (
	ManifestFile   = "manifest.dsse.json"
	ControlsFile   = "controls.json"
	RevokesFile    = "revocations.json"
	GraphFile      = "graph.json"
	IAMActionsFile = "iam-actions.json"

	manifestFormat = "compliancetf.bundle-manifest/v2"
	profileFormat  = "compliancetf.profile/v1"
	floorFormat    = "compliancetf.floor/v1"
	maxFile        = 16 << 20

	// ExpiryGrace is how long past expires_at a bundle still loads, with a warning.
	ExpiryGrace = 7 * 24 * time.Hour

	FloorOnline = "online"
	FloorAirgap = "airgap"

	maxProfileLifetime = 30 * 24 * time.Hour
	maxOnlineLifetime  = 24 * time.Hour
	maxAirgapLifetime  = 7 * 24 * time.Hour
	maxFloorBundles    = 256
	maxRetiredKeys     = 64
)

var (
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hexRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	semverRE   = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)
	knownFiles = map[string]bool{ControlsFile: true, RevokesFile: true, GraphFile: true, IAMActionsFile: true}
)

// ErrFloorRevocationPending: the floor names a revocation epoch no input
// bundle carries.
var ErrFloorRevocationPending = errors.New("floor revocation epoch pending")

// Inputs are the bytes of one gate run, each read once (ReadInputs).
// VerifyInputs copies them; Verified holds the only bytes evaluation may use.
type Inputs struct {
	OrgID   string        // the run org
	Keyring []byte        // compliancetf.keyring/v1; the floor binds its sha256
	Bundles []BundleFiles // one per bundle
	Profile []byte        // the org profile DSSE envelope
	Floor   []byte        // the floor statement DSSE envelope
}

// BundleFiles is one bundle: its manifest envelope and the files it lists,
// by manifest path.
type BundleFiles struct {
	Manifest []byte
	Files    map[string][]byte
}

// Verified is the outcome of VerifyInputs.
type Verified struct {
	Profile       *Profile
	ProfileDigest string // sha256 of the profile payload, as the provider's Profile.Digest
	Floor         *Floor
	Bundles       []VerifiedBundle // sorted by Digest
	BundleDigest  string           // BundleSetDigest of the bundle digests
	Revocations   Revocations      // the merged set
	Warnings      []string         // bundles inside their expiry grace
}

// VerifiedBundle is a bundle whose manifest signature and files verified.
type VerifiedBundle struct {
	Manifest *Manifest
	Digest   string            // sha256 of the raw manifest.dsse.json bytes
	KeyID    string            // manifest signing key
	Files    map[string][]byte // the digest-checked file bytes
}

// Manifest is the bundle manifest 2.0 payload.
type Manifest struct {
	Format        string `json:"format"`
	BundleID      string `json:"bundle_id"`
	BundleVersion int64  `json:"bundle_version"`
	Label         string `json:"label,omitempty"`
	OrgID         string `json:"org_id"`
	Profile       string `json:"profile"`
	CCM           struct {
		SnapshotID    string `json:"snapshot_id"`
		SchemaVersion string `json:"schema_version"`
	} `json:"ccm"`
	Provider struct {
		Address      string `json:"address"`
		VersionRange string `json:"version_range"`
	} `json:"provider"`
	Upstream struct {
		Source       string `json:"source"`
		VersionRange string `json:"version_range"`
	} `json:"upstream"`
	SchemaCompatDigest string      `json:"schema_compat_digest"`
	Files              []FileEntry `json:"files"`
	IssuedAt           string      `json:"issued_at"`
	ExpiresAt          string      `json:"expires_at"`
	MinBundleVersion   int64       `json:"min_bundle_version"`
	MinProfileVersion  int64       `json:"min_profile_version"`

	issued, expires time.Time
}

// FileEntry is one manifest files[] entry.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Profile is the part of a compliancetf.profile/v1 payload VerifyInputs
// checks; the other members stay raw for their consumers. Unknown top-level
// members fail.
type Profile struct {
	Format            string      `json:"format"`
	OrgID             string      `json:"org_id"`
	ProfileVersion    int64       `json:"profile_version"`
	IssuedAt          time.Time   `json:"issued_at"`
	ExpiresAt         time.Time   `json:"expires_at"`
	Governed          bool        `json:"governed"`
	MinWrapperVersion string      `json:"min_wrapper_version,omitempty"`
	FloorMode         string      `json:"floor_mode,omitempty"`
	FloorAirgapPath   string      `json:"floor_airgap_path,omitempty"`
	VerdictRequired   bool        `json:"verdict_required"`
	Bundles           []BundleMin `json:"bundles,omitempty"`
	RevokedKIDs       []string    `json:"revoked_kids,omitempty"`

	ModeFloor     json.RawMessage `json:"mode_floor"`
	Scope         json.RawMessage `json:"scope,omitempty"`
	ControlFloors json.RawMessage `json:"control_floors,omitempty"`
	DataSources   json.RawMessage `json:"data_sources,omitempty"`
	Exceptions    json.RawMessage `json:"exceptions"`
	Evidence      json.RawMessage `json:"evidence"`
	Budgets       json.RawMessage `json:"budgets"`
	Verdict       json.RawMessage `json:"verdict,omitempty"`
	Baseline      json.RawMessage `json:"baseline,omitempty"`
	BreakGlass    json.RawMessage `json:"break_glass,omitempty"`
}

// BundleMin is a profile bundles[] entry.
type BundleMin struct {
	BundleID   string `json:"bundle_id"`
	MinVersion int64  `json:"min_version"`
}

// Floor is an accepted floor statement.
type Floor struct {
	OrgID             string
	MinProfileVersion int64
	Bundles           map[string]int64
	MinWrapperVersion string
	Epoch             int64
	RevocationEpoch   int64
	RetiredKeys       []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	KeyID             string
	Generation        int64
}

// VerifyInputs verifies in at now. Any error means no input may be used.
func VerifyInputs(in Inputs, now time.Time) (*Verified, error) {
	kr, err := ParseKeyring(in.Keyring)
	if err != nil {
		return nil, err
	}
	// Each manifest verifies under the empty set, so the signature chosen
	// never depends on bundle order; the merged set is applied below.
	revs := NoRevocations()
	bundles := make([]VerifiedBundle, 0, len(in.Bundles))
	for i, b := range in.Bundles {
		vb, r, berr := verifyBundle(kr, b)
		if err = berr; err != nil {
			return nil, fmt.Errorf("bundle %d: %w", i, err)
		}
		if revs, err = Merge(revs, r); err != nil {
			return nil, err
		}
		bundles = append(bundles, vb)
	}
	if len(bundles) == 0 {
		return nil, errors.New("no bundles to load")
	}

	pv, err := kr.verify(in.Profile, PayloadProfile, revs)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	prof, err := parseProfile(pv.Payload)
	if err != nil {
		return nil, err
	}
	if prof.OrgID != in.OrgID {
		return nil, fmt.Errorf("profile: wrong org (want %q)", in.OrgID)
	}
	if prof.FloorMode == "" {
		return nil, errors.New("profile: floor_mode is required: a gate run needs a signed floor statement")
	}
	floor, err := kr.verifyFloor(in.Floor, in.OrgID, prof.FloorMode, sha256Digest(in.Keyring), now, revs)
	if err != nil {
		return nil, err
	}

	// Minimums: the floor statement and verified manifests of this org or public.
	pmin, bmin := floor.MinProfileVersion, maps.Clone(floor.Bundles)
	for _, b := range bundles {
		if m := b.Manifest; m.OrgID == "" || m.OrgID == in.OrgID {
			bmin[m.BundleID] = max(bmin[m.BundleID], m.MinBundleVersion)
			pmin = max(pmin, m.MinProfileVersion)
		}
	}
	switch {
	case !now.Before(prof.ExpiresAt):
		return nil, fmt.Errorf("profile: v%d expired %s", prof.ProfileVersion, prof.ExpiresAt.Format(time.RFC3339))
	case now.Before(prof.IssuedAt.Add(-Skew)):
		return nil, fmt.Errorf("profile: v%d issued in the future", prof.ProfileVersion)
	case prof.ProfileVersion < pmin:
		return nil, fmt.Errorf("profile: v%d is below the floor v%d", prof.ProfileVersion, pmin)
	}
	for _, r := range prof.Bundles {
		bmin[r.BundleID] = max(bmin[r.BundleID], r.MinVersion)
		if !slices.ContainsFunc(bundles, func(b VerifiedBundle) bool { return b.Manifest.BundleID == r.BundleID }) {
			return nil, fmt.Errorf("profile requires bundle %s, which is not an input", r.BundleID)
		}
	}
	for _, b := range bundles {
		m := b.Manifest
		switch {
		case m.BundleVersion < bmin[m.BundleID]:
			return nil, fmt.Errorf("bundle %s v%d is below the minimum v%d", m.BundleID, m.BundleVersion, bmin[m.BundleID])
		case m.MinProfileVersion > prof.ProfileVersion:
			return nil, fmt.Errorf("bundle %s v%d needs org profile v%d or later, run has v%d", m.BundleID, m.BundleVersion, m.MinProfileVersion, prof.ProfileVersion)
		}
	}

	// The provider's NewControlSet: digest order, unique ids, then Check.
	slices.SortFunc(bundles, func(a, b VerifiedBundle) int { return strings.Compare(a.Digest, b.Digest) })
	ids := map[string]bool{}
	var warns, digests []string
	for _, b := range bundles {
		if ids[b.Manifest.BundleID] {
			return nil, fmt.Errorf("duplicate bundle_id %s", b.Manifest.BundleID)
		}
		ids[b.Manifest.BundleID] = true
	}
	for _, b := range bundles {
		w, err := b.check(in.OrgID, now, revs)
		if err != nil {
			return nil, err
		}
		if w != "" {
			warns = append(warns, w)
		}
		digests = append(digests, b.Digest)
	}
	return &Verified{Profile: prof, ProfileDigest: sha256Digest(pv.Payload), Floor: floor, Bundles: bundles,
		BundleDigest: BundleSetDigest(digests), Revocations: revs, Warnings: warns}, nil
}

func sha256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// verifyBundle checks the manifest signature before parsing it, then that
// the files are exactly those listed, each with its size and sha256, before
// any is parsed.
func verifyBundle(kr *Keyring, b BundleFiles) (VerifiedBundle, Revocations, error) {
	v, err := kr.verify(b.Manifest, PayloadBundleManifest, NoRevocations())
	if err != nil {
		return VerifiedBundle{}, Revocations{}, err
	}
	m, err := parseManifest(v.Payload)
	if err != nil {
		return VerifiedBundle{}, Revocations{}, err
	}
	files := map[string][]byte{}
	for _, f := range m.Files {
		body, ok := b.Files[f.Path]
		switch {
		case !ok:
			return VerifiedBundle{}, Revocations{}, fmt.Errorf("%s: missing file listed in the manifest", f.Path)
		case int64(len(body)) != f.Size:
			return VerifiedBundle{}, Revocations{}, fmt.Errorf("%s: size does not match the manifest", f.Path)
		case sha256Digest(body) != "sha256:"+f.SHA256:
			return VerifiedBundle{}, Revocations{}, fmt.Errorf("%s: digest mismatch", f.Path)
		}
		files[f.Path] = bytes.Clone(body)
	}
	if len(b.Files) != len(files) {
		return VerifiedBundle{}, Revocations{}, errors.New("an entry is unlisted or duplicate")
	}
	revs := NoRevocations()
	if body, ok := files[RevokesFile]; ok {
		if revs, err = ParseRevocations(body); err != nil {
			return VerifiedBundle{}, Revocations{}, fmt.Errorf("%s: %w", RevokesFile, err)
		}
	}
	return VerifiedBundle{Manifest: m, Digest: sha256Digest(b.Manifest), KeyID: v.KeyID, Files: files}, revs, nil
}

var manifestNames = names("format", "bundle_id", "bundle_version", "label", "org_id", "profile", "ccm", "snapshot_id",
	"schema_version", "provider", "address", "version_range", "upstream", "source", "schema_compat_digest", "files",
	"path", "sha256", "size", "issued_at", "expires_at", "min_bundle_version", "min_profile_version")

// parseManifest is the provider's ParseManifest: strict decode, field rules,
// then the files rules.
func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	// The provider's three texts: trailing data, a decode error of valid
	// JSON (unknown member, wrong type), any other strict JSON breach.
	switch err := strictUnmarshal(data, manifestNames, &m); {
	case err == nil:
	case errors.Is(err, errTrailing):
		return nil, errors.New("manifest: trailing data")
	case (errors.Is(err, errUnknownName) || errors.Is(err, errWrongShape)) && json.Valid(data):
		return nil, errors.New("manifest: unknown member or wrong value type")
	default:
		return nil, errors.New("manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)")
	}
	switch {
	case m.Format != manifestFormat:
		return nil, fmt.Errorf("manifest format is not %s", manifestFormat)
	case !idRE.MatchString(m.BundleID) || m.BundleVersion < 1:
		return nil, errors.New("manifest bundle_id or bundle_version invalid")
	case m.MinBundleVersion < 0 || m.MinBundleVersion > m.BundleVersion || m.MinProfileVersion < 0:
		return nil, fmt.Errorf("manifest min_bundle_version %d / min_profile_version %d invalid", m.MinBundleVersion, m.MinProfileVersion)
	case m.Profile == "" || m.CCM.SnapshotID == "" || m.CCM.SchemaVersion == "" || m.Provider.Address == "" ||
		m.Provider.VersionRange == "" || m.Upstream.Source == "" || m.Upstream.VersionRange == "":
		return nil, errors.New("manifest needs profile, ccm.{snapshot_id,schema_version}, provider.{address,version_range} and upstream.{source,version_range}")
	case !reDigest.MatchString(m.SchemaCompatDigest):
		return nil, errors.New("manifest schema_compat_digest is not sha256:<hex>")
	}
	var err1, err2 error
	m.issued, err1 = time.Parse(time.RFC3339, m.IssuedAt)
	m.expires, err2 = time.Parse(time.RFC3339, m.ExpiresAt)
	if err1 != nil || err2 != nil || !m.expires.After(m.issued) {
		return nil, errors.New("manifest issued_at or expires_at invalid")
	}
	seen := map[string]bool{}
	for i, f := range m.Files {
		if !knownFiles[f.Path] || seen[f.Path] {
			return nil, fmt.Errorf("manifest file %d is unknown or listed twice", i)
		}
		if !hexRE.MatchString(f.SHA256) || f.Size < 0 || f.Size > maxFile {
			return nil, fmt.Errorf("manifest file %s: bad sha256 or size", f.Path)
		}
		seen[f.Path] = true
	}
	if !seen[ControlsFile] {
		return nil, errors.New("manifest files must list controls.json")
	}
	return &m, nil
}

// check is the provider's Bundle.Check: org, revocations (before expiry, so
// a revoked bundle gets no grace), a future issued_at, then expiry with
// ExpiryGrace. It returns a warning inside the grace window.
func (b VerifiedBundle) check(org string, now time.Time, revs Revocations) (string, error) {
	m := b.Manifest
	if m.OrgID != "" && m.OrgID != org {
		return "", fmt.Errorf("bundle %s is for another org, not %q", m.BundleID, org)
	}
	if revs.KeyRevoked(b.KeyID) || revs.BundleRevoked(m.BundleID, m.BundleVersion) {
		return "", fmt.Errorf("bundle %s v%d (%s) is revoked", m.BundleID, m.BundleVersion, b.Digest)
	}
	if m.issued.After(now.Add(Skew)) {
		return "", fmt.Errorf("bundle %s v%d issued_at %s is in the future", m.BundleID, m.BundleVersion, m.issued.UTC().Format(time.RFC3339))
	}
	switch end := m.expires.Add(ExpiryGrace); {
	case !now.After(m.expires):
		return "", nil
	case !now.After(end):
		return fmt.Sprintf("Bundle %s v%d expired %s; it stops loading after %s.",
			m.BundleID, m.BundleVersion, m.expires.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)), nil
	default:
		return "", fmt.Errorf("bundle expired: %s v%d expired %s, grace ended %s",
			m.BundleID, m.BundleVersion, m.expires.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	}
}

// parseProfile decodes a verified profile payload and checks the fields
// VerifyInputs reads, with the provider's Parse rules for them.
func parseProfile(payload []byte) (*Profile, error) {
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, errors.New("profile: unknown member or invalid value (types, RFC 3339 times, enforcement modes)")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("profile: trailing data")
	}
	err := func() error {
		switch {
		case p.Format != profileFormat:
			return fmt.Errorf("format is not %q", profileFormat)
		case !idRE.MatchString(p.OrgID):
			return fmt.Errorf("org_id: want %s", idRE)
		case p.ProfileVersion < 1:
			return errors.New("profile_version must be >= 1")
		case !p.IssuedAt.Before(p.ExpiresAt):
			return errors.New("expires_at must be after issued_at")
		case p.ExpiresAt.Sub(p.IssuedAt) > maxProfileLifetime:
			return errors.New("lifetime exceeds 30 days")
		case p.MinWrapperVersion != "" && !semverRE.MatchString(p.MinWrapperVersion):
			return errors.New("min_wrapper_version: want a semantic version")
		}
		switch p.FloorMode {
		case FloorOnline, FloorAirgap:
		case "":
			if p.Governed || len(p.Bundles) > 0 {
				return errors.New("floor_mode is required when governed or bundles are set")
			}
		default:
			return errors.New("floor_mode: want online or airgap")
		}
		if p.FloorAirgapPath != "" && p.FloorMode != FloorAirgap {
			return errors.New("floor_airgap_path needs floor_mode airgap")
		}
		seen := map[string]bool{}
		for i, b := range p.Bundles {
			if b.BundleID == "" || b.MinVersion < 1 || seen[b.BundleID] {
				return fmt.Errorf("bundles: bad or duplicate entry %d", i)
			}
			seen[b.BundleID] = true
		}
		for i, k := range p.RevokedKIDs {
			if !kidRE.MatchString(k) || slices.Contains(p.RevokedKIDs[:i], k) {
				return fmt.Errorf("revoked_kids: bad or duplicate entry %d", i)
			}
		}
		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	return &p, nil
}

// verifyFloor is the provider's trust.VerifyFloor without persisted state:
// floor keys, signature under the merged revocations, org, keyring digest,
// lifetime for the floor mode, issued_at, expiry, retired keys and the
// revocation epoch.
func (k *Keyring) verifyFloor(env []byte, org, mode, keyringDigest string, now time.Time, revs Revocations) (*Floor, error) {
	if err := k.checkFloorKeys(); err != nil {
		return nil, fmt.Errorf("floor for %s: %w (fail closed)", org, err)
	}
	var maxLife time.Duration
	switch mode {
	case FloorOnline:
		maxLife = maxOnlineLifetime
	case FloorAirgap:
		maxLife = maxAirgapLifetime
	default:
		return nil, errors.New("floor: floor_mode must be online or airgap")
	}
	v, err := k.verify(env, PayloadFloor, revs)
	if err != nil {
		return nil, fmt.Errorf("floor for %s: %w", org, err)
	}
	f, kd, err := parseFloor(v.Payload)
	if err != nil {
		return nil, fmt.Errorf("floor for %s: %w", org, err)
	}
	f.KeyID, f.Generation = v.KeyID, k.byKID[v.KeyID].Generation
	switch {
	case f.OrgID != org:
		return nil, fmt.Errorf("floor is for another org, not %q", org)
	case kd != keyringDigest:
		return nil, fmt.Errorf("org floor names another keyring than the %s this provider embeds: upgrade the provider", keyringDigest)
	case !f.ExpiresAt.After(f.IssuedAt) || f.ExpiresAt.Sub(f.IssuedAt) > maxLife:
		return nil, fmt.Errorf("floor for %s: lifetime %s exceeds %s for floor_mode %s", org, f.ExpiresAt.Sub(f.IssuedAt), maxLife, mode)
	case f.IssuedAt.After(now.Add(Skew)):
		return nil, fmt.Errorf("floor for %s: issued_at %s is in the future", org, f.IssuedAt.Format(time.RFC3339))
	case !now.Before(f.ExpiresAt):
		return nil, fmt.Errorf("floor for %s expired %s", org, f.ExpiresAt.Format(time.RFC3339))
	case slices.Contains(f.RetiredKeys, f.KeyID):
		return nil, fmt.Errorf("floor for %s is signed by %s, which it lists as retired", org, f.KeyID)
	}
	for _, kid := range f.RetiredKeys {
		if r := k.byKID[kid]; r != nil && r.Purpose == PurposeFloor && r.Generation >= f.Generation {
			return nil, fmt.Errorf("floor for %s signed by generation %d retires a key of generation %d", org, f.Generation, r.Generation)
		}
	}
	if have := revs.Epoch(); f.RevocationEpoch > have {
		return nil, fmt.Errorf("%w: floor for %s needs revocation epoch %d, provider has %d: fail closed until a bundle carrying the newer revocations loads",
			ErrFloorRevocationPending, org, f.RevocationEpoch, have)
	}
	return f, nil
}

// checkFloorKeys: the keyring holds exactly the current and the next floor
// key, of consecutive generations.
func (k *Keyring) checkFloorKeys() error {
	var gens []int64
	for _, key := range k.keys {
		if key.Purpose == PurposeFloor {
			gens = append(gens, key.Generation)
		}
	}
	if len(gens) != 2 {
		return fmt.Errorf("keyring: want exactly 2 floor keys (current and next), have %d", len(gens))
	}
	if lo, hi := min(gens[0], gens[1]), max(gens[0], gens[1]); hi != lo+1 {
		return fmt.Errorf("keyring: floor key generations %d and %d are not consecutive", lo, hi)
	}
	return nil
}

// parseFloor parses a floor payload; it returns the keyring_digest apart.
func parseFloor(payload []byte) (*Floor, string, error) {
	var p struct {
		Format            string           `json:"format"`
		OrgID             string           `json:"org_id"`
		MinProfileVersion *int64           `json:"min_profile_version"`
		Bundles           map[string]int64 `json:"bundles"`
		MinWrapperVersion *string          `json:"min_wrapper_version"`
		KeyringDigest     string           `json:"keyring_digest"`
		Epoch             int64            `json:"epoch"`
		RevocationEpoch   *int64           `json:"revocation_epoch"`
		RetiredKeys       []string         `json:"retired_keys"`
		IssuedAt          string           `json:"issued_at"`
		ExpiresAt         string           `json:"expires_at"`
	}
	if err := strictUnmarshal(payload, nil, &p); err != nil {
		return nil, "", err
	}
	if p.Format != floorFormat {
		return nil, "", fmt.Errorf("format is not %q", floorFormat)
	}
	if p.MinProfileVersion == nil || p.MinWrapperVersion == nil || p.RevocationEpoch == nil || p.Bundles == nil || p.RetiredKeys == nil {
		return nil, "", errors.New("min_profile_version, bundles, min_wrapper_version, revocation_epoch and retired_keys are required")
	}
	switch {
	case !idRE.MatchString(p.OrgID):
		return nil, "", errors.New("org_id is invalid")
	case !kidRE.MatchString(p.KeyringDigest):
		return nil, "", errors.New("keyring_digest is invalid")
	case p.Epoch < 1 || *p.RevocationEpoch < 0 || *p.MinProfileVersion < 0:
		return nil, "", errors.New("epoch must be >= 1, revocation_epoch and min_profile_version >= 0")
	case *p.MinWrapperVersion != "" && !semverRE.MatchString(*p.MinWrapperVersion):
		return nil, "", errors.New("min_wrapper_version is not a semantic version")
	case len(p.Bundles) > maxFloorBundles || len(p.RetiredKeys) > maxRetiredKeys:
		return nil, "", errors.New("too many bundles or retired_keys")
	}
	for id, v := range p.Bundles {
		if !idRE.MatchString(id) || v < 1 {
			return nil, "", errors.New("bundles has an invalid id or a version below 1")
		}
	}
	for i, kid := range p.RetiredKeys {
		if !kidRE.MatchString(kid) || i > 0 && kid <= p.RetiredKeys[i-1] {
			return nil, "", errors.New("retired_keys must be sorted, unique sha256 kids")
		}
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return nil, "", errNotRFC3339("issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return nil, "", errNotRFC3339("expires_at")
	}
	return &Floor{OrgID: p.OrgID, MinProfileVersion: *p.MinProfileVersion, Bundles: p.Bundles,
		MinWrapperVersion: *p.MinWrapperVersion, Epoch: p.Epoch, RevocationEpoch: *p.RevocationEpoch,
		RetiredKeys: p.RetiredKeys, IssuedAt: issued.UTC(), ExpiresAt: expires.UTC()}, p.KeyringDigest, nil
}
