package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test keys derive from public labels, so no private key is committed. The
// bundle and floor labels are the provider's (internal/trust/testkeys), so
// their public halves equal its ctftest keyring entries; the provider's
// test profile key is Ed25519, which ctfkit does not trust, so the profile
// key has its own label.
var (
	tkBundle    = labelKey("compliancetf.test-bundle-key/bobthecorp")
	tkBundle2   = labelKey("compliancetf.test-bundle-key-2/bobthecorp")
	tkProfile   = labelKey("compliancetf.test-profile-key-es256/bobthecorp")
	tkFloor     = labelKey("compliancetf.test-floor-key/bobthecorp")
	tkFloorNext = labelKey("compliancetf.test-floor-key-next/bobthecorp")
	// tkVerdict is the profile's verdict key, the key gate sign tests sign with.
	tkVerdict = labelKey("compliancetf.test-verdict-key/bobthecorp")
)

// Bundle controls in the provider's controls.json form (a JSON array of
// bundle 2.0 controls). The graph controls are the ones the gate fixtures
// decide: a companion_present control and its deletion guard.
const (
	cisControls = `[{"id":"cis_s3_bucket_versioning","version":"1.0.0","kind":"resource","resource_type":"aws_s3_bucket",` +
		`"reads":["versioning"],"presence_mode":"effective","on":["create","update"],"expr":"has(resource.versioning)",` +
		`"action":"deny","severity":"medium","message":"S3 bucket has no versioning.","exemption_coverable":["grant","self_service"]}]`
	soc2Controls = `[{"id":"s3_bucket_public_access_block_present","version":"1.0.0","kind":"graph","resource_type":"aws_s3_bucket",` +
		`"graph":{"rule":"companion_present","companion_type":"aws_s3_bucket_public_access_block","link_attr":"bucket","target_attrs":["id","bucket"]},` +
		`"action":"deny","severity":"high","message":"S3 bucket has no public access block.","exemption_coverable":["break_glass"]},` +
		`{"id":"s3_bucket_public_access_block_kept","version":"1.0.0","kind":"graph","resource_type":"aws_s3_bucket",` +
		`"graph":{"rule":"companion_absent_forbidden","companion_type":"aws_s3_bucket_public_access_block","link_attr":"bucket","target_attrs":["id","bucket"]},` +
		`"action":"deny","severity":"high","message":"The public access block of a kept bucket must not be removed.","exemption_coverable":[]}]`
	soc2Graph = `{"format":"compliancetf.graph/v1","controls":["s3_bucket_public_access_block_kept","s3_bucket_public_access_block_present"]}`
)

const inputsNow = "2026-10-19T12:00:00Z"

func labelKey(label string) *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err)
	}
	return k
}

func kidOf(k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return KeyID(der)
}

func spkiB64(k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// envelope signs payload with keys (none: an unsigned envelope).
func envelope(payloadType string, payload []byte, keys ...*ecdsa.PrivateKey) []byte {
	sigs := []map[string]string{}
	for _, k := range keys {
		d := sha256.Sum256(PAE(payloadType, payload))
		sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, map[string]string{"keyid": kidOf(k), "sig": base64.StdEncoding.EncodeToString(sig)})
	}
	return mustJSON(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": sigs})
}

// inputCase is one testdata/inputs case before signing; mutate changes it.
type inputCase struct {
	profile, floor map[string]any
	bundles        map[string]*genBundle
	keyring        []byte
}

type genBundle struct {
	manifest map[string]any
	files    map[string][]byte
	key      *ecdsa.PrivateKey
	unsigned bool
	after    func(files map[string][]byte) // changes files after signing
}

func baseCase() *inputCase {
	kr := []map[string]any{}
	for _, k := range []struct {
		key     *ecdsa.PrivateKey
		purpose string
		gen     int64
	}{{tkBundle, PurposeBundle, 0}, {tkBundle2, PurposeBundle, 0}, {tkProfile, PurposeProfile, 0}, {tkFloor, PurposeFloor, 1}, {tkFloorNext, PurposeFloor, 2}} {
		der, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
		if err != nil {
			panic(err)
		}
		e := map[string]any{"kid": KeyID(der), "alg": AlgES256, "purpose": []string{k.purpose},
			"public_key": base64.StdEncoding.EncodeToString(der), "not_before": "2026-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z"}
		if k.gen > 0 {
			e["generation"] = k.gen
		}
		kr = append(kr, e)
	}
	keyring := mustJSON(map[string]any{"format": keyringFormat, "keys": kr})
	manifest := func(id, org string, version int64) map[string]any {
		return map[string]any{"format": manifestFormat, "bundle_id": id, "bundle_version": version, "org_id": org, "profile": "aws",
			"ccm":                  map[string]any{"snapshot_id": "snap-1", "schema_version": "1"},
			"provider":             map[string]any{"address": "registry.compliance.tf/compliancetf/aws", "version_range": ">= 2.0.0"},
			"upstream":             map[string]any{"source": "registry.terraform.io/hashicorp/aws", "version_range": ">= 6.0.0"},
			"schema_compat_digest": "sha256:" + hex.EncodeToString(make([]byte, 32)),
			"issued_at":            "2026-10-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "min_bundle_version": int64(1), "min_profile_version": int64(1)}
	}
	return &inputCase{
		keyring: keyring,
		profile: map[string]any{"format": profileFormat, "org_id": "bobthecorp", "profile_version": 7,
			"issued_at": "2026-10-10T00:00:00Z", "expires_at": "2026-11-01T00:00:00Z", "governed": true, "floor_mode": FloorOnline,
			"verdict_required": true, "mode_floor": map[string]any{"default": "hard_fail"}, "bundles": []map[string]any{{"bundle_id": "bobthecorp-soc2", "min_version": 13}},
			"exceptions": map[string]any{}, "evidence": map[string]any{"required": false}, "budgets": map[string]any{},
			"scope": map[string]any{"workspace": "default"},
			"verdict": map[string]any{"max_ttl": "24h", "public_keys": []map[string]any{{"kid": kidOf(tkVerdict), "alg": AlgES256, "use": "verdict",
				"spki_b64": spkiB64(tkVerdict), "not_before": "2026-10-01T00:00:00Z", "not_after": "2026-11-01T00:00:00Z"}}}},
		floor: map[string]any{"format": floorFormat, "org_id": "bobthecorp", "min_profile_version": 7,
			"bundles": map[string]int64{"cis-aws": 5, "bobthecorp-soc2": 13}, "min_wrapper_version": "1.0.0",
			"keyring_digest": sha256Digest(keyring), "epoch": 7, "revocation_epoch": 1, "retired_keys": []string{},
			"issued_at": "2026-10-19T06:00:00Z", "expires_at": "2026-10-20T00:00:00Z"},
		bundles: map[string]*genBundle{
			"cis-aws": {manifest: manifest("cis-aws", "", 5), key: tkBundle2, files: map[string][]byte{
				ControlsFile: []byte(cisControls)}},
			"bobthecorp-soc2": {manifest: manifest("bobthecorp-soc2", "bobthecorp", 13), key: tkBundle, files: map[string][]byte{
				ControlsFile: []byte(soc2Controls),
				GraphFile:    []byte(soc2Graph),
				RevokesFile:  revocationsJSON(1, nil)}},
		},
	}
}

func revocationsJSON(epoch int64, revokedKIDs []string) []byte {
	keys := []map[string]string{}
	for _, k := range revokedKIDs {
		keys = append(keys, map[string]string{"kid": k, "revoked_at": "2026-10-15T00:00:00Z"})
	}
	return mustJSON(map[string]any{"format": revocationsFormat, "epoch": epoch, "revoked_keys": keys,
		"revoked_bundles": []any{}, "revoked_controls": []any{}})
}

func evidenceSinks() map[string]any {
	return map[string]any{"required": true, "sinks": []map[string]any{{"type": "s3_object_lock",
		"bucket": "bobthecorp-evidence", "prefix": "compliancetf/", "min_retention_days": 365}}}
}

// inputCases are the testdata/inputs cases and the error each must give
// ("" accepts).
var inputCases = []struct {
	name, want string
	mutate     func(c *inputCase)
}{
	{"valid", "", func(*inputCase) {}},
	// airgap and permissive are valid too: ctfkit apply's floor_mode airgap
	// time source, and an advisory run mode whose control floor still makes
	// the companion_present control block.
	{"airgap", "", func(c *inputCase) { c.profile["floor_mode"] = FloorAirgap }},
	{"permissive", "", func(c *inputCase) {
		c.profile["mode_floor"] = map[string]any{"default": "advisory"}
		c.profile["control_floors"] = map[string]any{"s3_bucket_public_access_block_present": "hard_fail"}
	}},
	// evidence and evidence-advisory list an S3 Object Lock evidence sink, for
	// ctfkit evidence ship; evidence-advisory has no verdict_required.
	{"evidence", "", func(c *inputCase) { c.profile["evidence"] = evidenceSinks() }},
	{"evidence-advisory", "", func(c *inputCase) {
		c.profile["evidence"] = evidenceSinks()
		c.profile["verdict_required"] = false
	}},
	{"altered-graph-rule", "graph.json: digest mismatch", func(c *inputCase) {
		c.bundles["bobthecorp-soc2"].after = func(f map[string][]byte) {
			f[GraphFile] = []byte(strings.Replace(soc2Graph, "_kept", "_Kept", 1)) // same size
		}
	}},
	{"unlisted-file", "an entry is unlisted or duplicate", func(c *inputCase) {
		c.bundles["cis-aws"].after = func(f map[string][]byte) { f[IAMActionsFile] = []byte(`{}`) }
	}},
	{"unsigned-manifest", "need 1 to 8 signatures", func(c *inputCase) { c.bundles["bobthecorp-soc2"].unsigned = true }},
	{"expired-profile", "profile: v7 expired 2026-10-18T00:00:00Z", func(c *inputCase) {
		c.profile["issued_at"], c.profile["expires_at"] = "2026-10-01T00:00:00Z", "2026-10-18T00:00:00Z"
	}},
	{"below-floor", "profile: v6 is below the floor v7", func(c *inputCase) { c.profile["profile_version"] = 6 }},
	{"bundle-below-floor", "bundle cis-aws v5 is below the minimum v6", func(c *inputCase) {
		c.floor["bundles"] = map[string]int64{"cis-aws": 6, "bobthecorp-soc2": 13}
	}},
	{"revoked-key", "profile: dsse: no valid signature: signature 0: key revoked", func(c *inputCase) {
		c.bundles["bobthecorp-soc2"].files[RevokesFile] = revocationsJSON(1, []string{kidOf(tkProfile)})
	}},
	{"revoked-bundle-key", "is revoked", func(c *inputCase) {
		c.bundles["bobthecorp-soc2"].files[RevokesFile] = revocationsJSON(1, []string{kidOf(tkBundle2)})
	}},
	{"floor-revocation-pending", "floor revocation epoch pending", func(c *inputCase) { c.floor["revocation_epoch"] = 2 }},
	{"floor-wrong-keyring", "names another keyring", func(c *inputCase) {
		c.floor["keyring_digest"] = "sha256:" + hex.EncodeToString(make([]byte, 32))
	}},
}

// generateInputs rewrites testdata/inputs.
func generateInputs(t *testing.T) {
	t.Helper()
	root := filepath.Join("testdata", "inputs")
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	for _, tc := range inputCases {
		c := baseCase()
		tc.mutate(c)
		dir := filepath.Join(root, tc.name)
		write := func(name string, b []byte) {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // public test data
				t.Fatal(err)
			}
		}
		write("keyring.json", c.keyring)
		profile := mustJSON(c.profile)
		write("profile.dsse.json", envelope(PayloadProfile, profile, tkProfile))
		write("floor.dsse.json", envelope(PayloadFloor, mustJSON(c.floor), tkFloor))
		var digests []string
		for id, b := range c.bundles {
			files := []FileEntry{}
			for _, name := range []string{ControlsFile, GraphFile, IAMActionsFile, RevokesFile} {
				if body, ok := b.files[name]; ok {
					s := sha256.Sum256(body)
					files = append(files, FileEntry{Path: name, SHA256: hex.EncodeToString(s[:]), Size: int64(len(body))})
				}
			}
			b.manifest["files"] = files
			var keys []*ecdsa.PrivateKey
			if !b.unsigned {
				keys = append(keys, b.key)
			}
			env := envelope(PayloadBundleManifest, mustJSON(b.manifest), keys...)
			digests = append(digests, sha256Digest(env))
			if b.after != nil {
				b.after(b.files)
			}
			write(filepath.Join("bundles", id, ManifestFile), env)
			for name, body := range b.files {
				write(filepath.Join("bundles", id, name), body)
			}
		}
		want := map[string]any{"error": tc.want}
		if tc.want == "" {
			want = map[string]any{"bundle_digest": BundleSetDigest(digests), "profile_digest": sha256Digest(profile), "floor_epoch": 7}
		}
		write("expected.json", append(mustJSON(want), '\n'))
	}
}
