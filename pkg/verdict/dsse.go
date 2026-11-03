package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DSSE envelopes, the release keyring and revocation sets, ported from the
// provider's internal/trust (dsse.go, keyring.go, revocations.go) with the
// same rules, check order and error texts. Unlike the provider, ctfkit
// compiles in no key: the caller passes the keyring bytes, and only ES256
// keys are trusted (the provider allows Ed25519 in ctftest builds only).

// DSSE payload types.
const (
	PayloadBundleManifest = "application/vnd.compliancetf.bundle-manifest+json;v=2"
	PayloadProfile        = "application/vnd.compliancetf.profile+json;v=1"
	PayloadFloor          = "application/vnd.compliancetf.floor+json;v=1"
)

// Keyring key purposes.
const (
	PurposeBundle    = "bundle"
	PurposeProfile   = "profile"
	PurposeFloor     = "floor"
	PurposeException = "exception"
)

var purposeFor = map[string]string{
	PayloadBundleManifest: PurposeBundle,
	PayloadProfile:        PurposeProfile,
	PayloadFloor:          PurposeFloor,
}

const (
	maxEnvelopeBytes    = 4 << 20
	maxSignatures       = 8
	maxKeyIDLen         = 80
	maxSigB64Len        = 256
	maxES256SigLen      = 72
	keyringFormat       = "compliancetf.keyring/v1"
	maxKeyringBytes     = 1 << 20
	maxKeyringKeys      = 64
	revocationsFormat   = "compliancetf.revocations/v1"
	maxRevocationsBytes = 1 << 20
	maxRevocationsList  = 4096
)

var kidRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// TrustKey is one release keyring key. Generation is set only for floor keys.
type TrustKey struct {
	KID, Purpose        string
	Generation          int64
	NotBefore, NotAfter time.Time
	pub                 *ecdsa.PublicKey
}

// Keyring is a parsed compliancetf.keyring/v1 file.
type Keyring struct {
	keys  []TrustKey
	byKID map[string]*TrustKey
}

var keyringNames = names("format", "keys", "kid", "alg", "purpose", "generation", "public_key", "not_before", "not_after")

// ParseKeyring parses a keyring file; any bad entry or a kid listed twice
// fails the whole file.
func ParseKeyring(data []byte) (*Keyring, error) {
	if len(data) > maxKeyringBytes {
		return nil, errors.New("keyring: file too large")
	}
	var f struct {
		Format string `json:"format"`
		Keys   []struct {
			KID        string   `json:"kid"`
			Alg        string   `json:"alg"`
			Purpose    []string `json:"purpose"`
			Generation *int64   `json:"generation"`
			PublicKey  string   `json:"public_key"`
			NotBefore  string   `json:"not_before"`
			NotAfter   string   `json:"not_after"`
		} `json:"keys"`
	}
	if err := strictUnmarshal(data, keyringNames, &f); err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if f.Format != keyringFormat {
		return nil, fmt.Errorf("keyring: format %q, want %q", f.Format, keyringFormat)
	}
	if len(f.Keys) > maxKeyringKeys {
		return nil, fmt.Errorf("keyring: more than %d keys", maxKeyringKeys)
	}
	kr := &Keyring{keys: make([]TrustKey, len(f.Keys)), byKID: map[string]*TrustKey{}}
	for i, e := range f.Keys {
		k := &kr.keys[i]
		err := func() error {
			if !kidRE.MatchString(e.KID) {
				return fmt.Errorf("kid %q is not sha256:<64 lowercase hex>", e.KID)
			}
			der, err := base64.StdEncoding.Strict().DecodeString(e.PublicKey)
			if err != nil {
				return fmt.Errorf("public_key: %w", err)
			}
			if KeyID(der) != e.KID {
				return fmt.Errorf("kid %s does not match public_key", e.KID)
			}
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return fmt.Errorf("public_key: %w", err)
			}
			switch e.Alg {
			case AlgES256:
			case "Ed25519": // the provider's release-build text
				return errors.New("alg Ed25519 is not trusted in this build")
			default:
				return fmt.Errorf("alg %q not allowed", e.Alg)
			}
			ec, ok := pub.(*ecdsa.PublicKey)
			if !ok || ec.Curve != elliptic.P256() {
				return errors.New("ES256 key is not ECDSA P-256")
			}
			k.KID, k.pub = e.KID, ec
			if len(e.Purpose) != 1 {
				return errors.New("purpose must list exactly one entry")
			}
			switch k.Purpose = e.Purpose[0]; k.Purpose {
			case PurposeBundle, PurposeProfile, PurposeException:
				if e.Generation != nil {
					return errors.New("generation is only allowed on floor keys")
				}
			case PurposeFloor:
				if e.Generation == nil || *e.Generation < 1 {
					return errors.New("floor key needs generation >= 1")
				}
				k.Generation = *e.Generation
			default:
				return fmt.Errorf("unknown purpose %q", k.Purpose)
			}
			if k.NotBefore, err = time.Parse(time.RFC3339, e.NotBefore); err != nil {
				return fmt.Errorf("not_before: %w", err)
			}
			if k.NotAfter, err = time.Parse(time.RFC3339, e.NotAfter); err != nil {
				return fmt.Errorf("not_after: %w", err)
			}
			if !k.NotBefore.Before(k.NotAfter) {
				return errors.New("not_before must be before not_after")
			}
			return nil
		}()
		if err != nil {
			return nil, fmt.Errorf("keyring: key %d: %w", i, err)
		}
	}
	for i := range kr.keys {
		k := &kr.keys[i]
		if kr.byKID[k.KID] != nil {
			return nil, fmt.Errorf("keyring: duplicate kid %s", k.KID)
		}
		kr.byKID[k.KID] = k
	}
	return kr, nil
}

// PAE is the DSSE v1 pre-authentication encoding; lengths are byte counts.
func PAE(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " +
		strconv.Itoa(len(payload)) + " " + string(payload))
}

// dsseResult is a verified envelope.
type dsseResult struct {
	Payload  []byte // the exact signed payload bytes
	KeyID    string // first accepted signature in envelope order
	IssuedAt time.Time
}

var envelopeNames = names("payloadType", "payload", "signatures", "keyid", "sig")

// verify checks a DSSE envelope as the provider's Keyring.Verify does.
// Structural problems reject the envelope; a signature with an unknown kid,
// wrong purpose, revoked kid, bad signature or a payload issued_at outside
// its key window is skipped. The first passing signature wins. Wall-clock
// time is not checked here.
func (k *Keyring) verify(env []byte, payloadType string, revs Revocations) (dsseResult, error) {
	if !revs.valid {
		return dsseResult{}, errors.New("dsse: invalid revocation set")
	}
	purpose, ok := purposeFor[payloadType]
	if !ok {
		return dsseResult{}, errors.New("dsse: unknown payload type")
	}
	if len(env) > maxEnvelopeBytes {
		return dsseResult{}, errors.New("dsse: envelope too large")
	}
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := strictUnmarshal(env, envelopeNames, &e); errors.Is(err, errWrongShape) {
		return dsseResult{}, errors.New("dsse: envelope has the wrong shape")
	} else if err != nil {
		return dsseResult{}, fmt.Errorf("dsse: %w", err)
	}
	if e.PayloadType != payloadType {
		return dsseResult{}, fmt.Errorf("dsse: payload type mismatch, want %q", payloadType)
	}
	if len(e.Signatures) < 1 || len(e.Signatures) > maxSignatures {
		return dsseResult{}, fmt.Errorf("dsse: need 1 to %d signatures", maxSignatures)
	}
	b64 := base64.StdEncoding.Strict()
	sigs := make([][]byte, len(e.Signatures))
	seen := map[string]bool{}
	for i, s := range e.Signatures {
		if len(s.KeyID) > maxKeyIDLen || !kidRE.MatchString(s.KeyID) {
			return dsseResult{}, fmt.Errorf("dsse: signature %d: bad keyid", i)
		}
		if seen[s.KeyID] {
			return dsseResult{}, fmt.Errorf("dsse: signature %d: duplicate keyid", i)
		}
		seen[s.KeyID] = true
		if len(s.Sig) > maxSigB64Len {
			return dsseResult{}, fmt.Errorf("dsse: signature %d too long", i)
		}
		var err error
		if sigs[i], err = b64.DecodeString(s.Sig); err != nil {
			return dsseResult{}, fmt.Errorf("dsse: signature %d: invalid base64", i)
		}
	}
	payload, err := b64.DecodeString(e.Payload)
	if err != nil {
		return dsseResult{}, errors.New("dsse: payload: invalid base64")
	}
	digest := sha256.Sum256(PAE(payloadType, payload))

	var reasons []string
	var issuedAt *time.Time
	for i, s := range e.Signatures {
		key := k.byKID[s.KeyID]
		switch {
		case key == nil:
			reasons = append(reasons, fmt.Sprintf("signature %d: key not in keyring", i))
			continue
		case key.Purpose != purpose:
			reasons = append(reasons, fmt.Sprintf("signature %d: key purpose %s, payload needs %s", i, key.Purpose, purpose))
			continue
		case revs.KeyRevoked(s.KeyID):
			reasons = append(reasons, fmt.Sprintf("signature %d: key revoked", i))
			continue
		case len(sigs[i]) > maxES256SigLen || !ecdsa.VerifyASN1(key.pub, digest[:], sigs[i]):
			reasons = append(reasons, fmt.Sprintf("signature %d: signature invalid", i))
			continue
		}
		if issuedAt == nil {
			t, err := payloadIssuedAt(payload)
			if err != nil {
				return dsseResult{}, fmt.Errorf("dsse: payload: %w", err)
			}
			issuedAt = &t
		}
		if issuedAt.Before(key.NotBefore) || issuedAt.After(key.NotAfter) {
			reasons = append(reasons, fmt.Sprintf("signature %d: issued_at %s outside key window", i, issuedAt.Format(time.RFC3339)))
			continue
		}
		return dsseResult{Payload: payload, KeyID: s.KeyID, IssuedAt: *issuedAt}, nil
	}
	return dsseResult{}, fmt.Errorf("dsse: no valid signature: %s", strings.Join(reasons, "; "))
}

// payloadIssuedAt reads the required top-level RFC 3339 issued_at of a
// signed payload, a single JSON object without duplicate member names.
func payloadIssuedAt(payload []byte) (time.Time, error) {
	if err := checkJSON(payload, nil); err != nil {
		return time.Time{}, err
	}
	var p struct {
		IssuedAt *string `json:"issued_at"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return time.Time{}, errWrongShape
	}
	if p.IssuedAt == nil {
		return time.Time{}, errors.New("issued_at missing")
	}
	t, err := time.Parse(time.RFC3339, *p.IssuedAt)
	if err != nil {
		return time.Time{}, errNotRFC3339("issued_at")
	}
	return t.UTC(), nil
}

// errNotRFC3339 replaces a time.Parse error, which quotes the value.
func errNotRFC3339(field string) error {
	return fmt.Errorf("%s is not an RFC 3339 time", field)
}

// Revocations is an immutable revocation set. The zero value is invalid:
// every query reports revoked and verify fails closed.
type Revocations struct {
	valid    bool
	epoch    int64
	keys     map[string]time.Time
	bundles  map[string]int64
	controls map[controlRef]bool
}

type controlRef struct {
	id      string
	version int64
}

var revocationsNames = names("format", "epoch", "revoked_keys", "kid", "revoked_at",
	"revoked_bundles", "bundle_id", "below_version", "revoked_controls", "id", "version")

// NoRevocations returns a valid, empty set.
func NoRevocations() Revocations {
	return Revocations{valid: true, keys: map[string]time.Time{}, bundles: map[string]int64{}, controls: map[controlRef]bool{}}
}

// ParseRevocations parses a revocations.json file. Callers pass only bytes
// whose digest a verified manifest binds.
func ParseRevocations(data []byte) (Revocations, error) {
	if len(data) > maxRevocationsBytes {
		return Revocations{}, errors.New("revocations: file too large")
	}
	var f struct {
		Format      string `json:"format"`
		Epoch       int64  `json:"epoch"`
		RevokedKeys []struct {
			KID       string `json:"kid"`
			RevokedAt string `json:"revoked_at"`
		} `json:"revoked_keys"`
		RevokedBundles []struct {
			BundleID     string `json:"bundle_id"`
			BelowVersion int64  `json:"below_version"`
		} `json:"revoked_bundles"`
		RevokedControls []struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		} `json:"revoked_controls"`
	}
	if err := strictUnmarshal(data, revocationsNames, &f); err != nil {
		return Revocations{}, fmt.Errorf("revocations: %w", err)
	}
	switch {
	case f.Format != revocationsFormat:
		return Revocations{}, fmt.Errorf("revocations: format is not %q", revocationsFormat)
	case f.Epoch < 1:
		return Revocations{}, errors.New("revocations: epoch must be >= 1")
	case len(f.RevokedKeys) > maxRevocationsList || len(f.RevokedBundles) > maxRevocationsList || len(f.RevokedControls) > maxRevocationsList:
		return Revocations{}, fmt.Errorf("revocations: list longer than %d", maxRevocationsList)
	}
	r := NoRevocations()
	r.epoch = f.Epoch
	for _, k := range f.RevokedKeys {
		if !kidRE.MatchString(k.KID) {
			return Revocations{}, errors.New("revocations: a revoked kid is not a sha256 kid")
		}
		at, err := time.Parse(time.RFC3339, k.RevokedAt)
		if err != nil {
			return Revocations{}, fmt.Errorf("revocations: %w", errNotRFC3339("revoked_at"))
		}
		if _, dup := r.keys[k.KID]; dup {
			return Revocations{}, errors.New("revocations: duplicate kid")
		}
		r.keys[k.KID] = at
	}
	for _, b := range f.RevokedBundles {
		if b.BundleID == "" || b.BelowVersion < 1 {
			return Revocations{}, errors.New("revocations: bundle entry needs bundle_id and below_version >= 1")
		}
		if _, dup := r.bundles[b.BundleID]; dup {
			return Revocations{}, errors.New("revocations: duplicate bundle_id")
		}
		r.bundles[b.BundleID] = b.BelowVersion
	}
	for _, c := range f.RevokedControls {
		ref := controlRef{c.ID, c.Version}
		if c.ID == "" || c.Version < 1 {
			return Revocations{}, errors.New("revocations: control entry needs id and version >= 1")
		}
		if r.controls[ref] {
			return Revocations{}, errors.New("revocations: duplicate control")
		}
		r.controls[ref] = true
	}
	return r, nil
}

// Merge returns the max epoch and the union of both sets; a kid keeps its
// earliest revoked_at, a bundle its highest below_version.
func Merge(a, b Revocations) (Revocations, error) {
	if !a.valid || !b.valid {
		return Revocations{}, errors.New("revocations: merge of an invalid set")
	}
	r := Revocations{valid: true, epoch: max(a.epoch, b.epoch),
		keys: maps.Clone(a.keys), bundles: maps.Clone(a.bundles), controls: maps.Clone(a.controls)}
	for kid, at := range b.keys {
		if old, ok := r.keys[kid]; !ok || at.Before(old) {
			r.keys[kid] = at
		}
	}
	for id, v := range b.bundles {
		r.bundles[id] = max(r.bundles[id], v)
	}
	maps.Copy(r.controls, b.controls)
	return r, nil
}

// Epoch is the revocation epoch (0 for NoRevocations).
func (r Revocations) Epoch() int64 { return r.epoch }

// KeyRevoked reports whether kid is revoked, whatever its revoked_at.
func (r Revocations) KeyRevoked(kid string) bool {
	_, ok := r.keys[kid]
	return ok || !r.valid
}

// BundleRevoked reports whether version of bundleID is below its revoked floor.
func (r Revocations) BundleRevoked(bundleID string, version int64) bool {
	return version < r.bundles[bundleID] || !r.valid
}

// ControlRevoked reports whether control id@version is revoked.
func (r Revocations) ControlRevoked(id string, version int64) bool {
	return r.controls[controlRef{id, version}] || !r.valid
}
