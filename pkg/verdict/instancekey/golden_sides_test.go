package instancekey_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/tfjson"
	"github.com/compliancetf/ctfkit/pkg/verdict/tfvalue"
)

// TestGoldenSides: both adapters reproduce the frozen expected.json of each
// type in goldenSides. The plan side (tfjson) reads plan.json and
// schema.json. The apply side (tfvalue) reads the apply requests the
// provider's record build tag dumped (apply/, envelope/, SOURCE.json; see
// scripts/record-instancekey-apply.sh) and derives form and prior kind as the
// provider does (internal/lifecycle instanceKey). The cross-side check then
// keys every recorded request with the plan side's unknown paths and kind
// and needs the plan side's key: the two sides agree on hashed keys without
// expected.json. Unknowns differ in shape (paths on the plan side, Unknown
// markers in the msgpack value), so the sides compare keys, never trees.
func TestGoldenSides(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(goldenDir, "aws_*"))
	if err != nil || len(dirs) != len(goldenSides) {
		t.Fatalf("%d golden types, %d in goldenSides (%v)", len(dirs), len(goldenSides), err)
	}
	for _, typ := range goldenSides {
		t.Run(typ, func(t *testing.T) { goldenSide(t, filepath.Join(goldenDir, typ), typ) })
	}
}

const goldenDir = "../testdata/instancekey"

// goldenSides are the types with recorded apply requests: all 20 frozen
// types (two batches).
var goldenSides = []string{
	"aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration",
	"aws_s3_bucket_versioning", "aws_security_group", "aws_vpc_security_group_ingress_rule",
	"aws_cloudwatch_log_group", "aws_kms_key", "aws_instance", "aws_sns_topic",
	"aws_cloudwatch_metric_alarm", "aws_db_instance", "aws_dynamodb_table", "aws_ebs_volume", "aws_iam_role",
	"aws_iam_role_policy_attachment", "aws_lambda_function", "aws_rds_cluster", "aws_secretsmanager_secret_version",
	"aws_sqs_queue",
}

type sideKey struct {
	Field             string     `json:"field"`
	Form              string     `json:"form"`
	Key               string     `json:"key"`
	PriorIdentityKind string     `json:"prior_identity_kind"`
	UnknownPaths      [][]string `json:"unknown_paths"`
}

type sideSource struct {
	ProviderCommit string `json:"provider_commit"`
	Records        []struct {
		Address string            `json:"address"`
		Deposed string            `json:"deposed"`
		Form    string            `json:"form"`
		SHA256  map[string]string `json:"sha256"`
	} `json:"records"`
}

func readGolden(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeGolden(t *testing.T, path string, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(readGolden(t, path)))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func goldenSide(t *testing.T, dir, typ string) {
	var exp struct {
		KLeafHex string `json:"k_leaf_hex"`
		Entries  []struct {
			Address string    `json:"address"`
			Deposed string    `json:"deposed"`
			Keys    []sideKey `json:"keys"`
		} `json:"entries"`
	}
	decodeGolden(t, filepath.Join(dir, "expected.json"), &exp)
	var leaf [32]byte
	if b, err := hex.DecodeString(exp.KLeafHex); err != nil || copy(leaf[:], b) != len(leaf) {
		t.Fatalf("k_leaf_hex: %v", err)
	}
	want := map[string]sideKey{} // address/deposed/form
	for _, e := range exp.Entries {
		for _, k := range e.Keys {
			want[e.Address+"/"+e.Deposed+"/"+k.Form] = k
		}
	}

	// Plan side.
	schemas, err := tfjson.ParseSchemas(readGolden(t, filepath.Join(dir, "schema.json")))
	if err != nil {
		t.Fatal(err)
	}
	insts, err := tfjson.Instances(leaf, readGolden(t, filepath.Join(dir, "plan.json")), schemas)
	if err != nil || len(insts) != len(exp.Entries) {
		t.Fatalf("plan side: %d instances for %d entries (%v)", len(insts), len(exp.Entries), err)
	}
	planKeys := map[string]tfjson.KeyInput{}
	for i, in := range insts {
		e := exp.Entries[i]
		got := []sideKey{}
		for _, k := range in.Keys {
			got = append(got, sideKey{k.Field, string(k.Form), k.Key, k.PriorIdentityKind, k.UnknownPaths})
			planKeys[in.Address+"/"+in.Deposed+"/"+string(k.Form)] = k
		}
		if in.Address != e.Address || in.Deposed != e.Deposed || in.Err != nil || !reflect.DeepEqual(got, e.Keys) {
			t.Errorf("plan side %s/%s (%v):\n got  %+v\n want %+v", in.Address, in.Deposed, in.Err, got, e.Keys)
		}
	}

	// Apply side: the recorded requests, one per key.
	var src sideSource
	decodeGolden(t, filepath.Join(dir, "SOURCE.json"), &src)
	if len(src.ProviderCommit) != 40 || len(src.Records) != len(want) {
		t.Fatalf("SOURCE.json: commit %q, %d records for %d keys", src.ProviderCommit, len(src.Records), len(want))
	}
	ids := priorIDs(t, filepath.Join(dir, "plan.json"))
	seen := map[string]bool{}
	for _, r := range src.Records {
		name := r.Address + "/" + r.Deposed + "/" + r.Form
		w, ok := want[name]
		if !ok || seen[name] {
			t.Errorf("%s: record has no expected key or repeats one", name)
			continue
		}
		seen[name] = true
		files := map[string][]byte{}
		for f, sum := range r.SHA256 {
			b := readGolden(t, filepath.Join(dir, f))
			if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != sum {
				t.Fatalf("%s: sha256 differs from SOURCE.json", f)
			}
			files[f] = b
		}
		base := r.Address + "." + r.Form
		if r.Deposed != "" {
			base = r.Address + "." + r.Deposed + "." + r.Form
		}
		planned, kind, prior := applyRequest(t, name, files["apply/"+base+".msgpack"], files["apply/"+base+".type.json"], files["envelope/"+base+".json"], instancekey.Form(r.Form), ids[r.Address+"/"+r.Deposed])
		if kind != w.PriorIdentityKind {
			t.Errorf("%s: apply side kind %s, want %s", name, kind, w.PriorIdentityKind)
			continue
		}
		got, err := tfvalue.Key(leaf, typ, instancekey.Form(r.Form), planned, w.UnknownPaths, prior)
		if err != nil || got != w.Key {
			t.Errorf("%s: apply side key %s (%v), want %s", name, got, err, w.Key)
		}

		// Cross side: no expected.json, only the plan side's key inputs.
		pk := planKeys[name]
		cross, err := tfvalue.Key(leaf, typ, pk.Form, planned, pk.UnknownPaths, prior)
		if err != nil || kind != pk.PriorIdentityKind || cross != pk.Key {
			t.Errorf("%s: cross side key %s kind %s (%v), plan side %s kind %s", name, cross, kind, err, pk.Key, pk.PriorIdentityKind)
		}
	}
}

// applyRequest is the PlannedState, prior identity kind and prior identity
// tree the provider keys a recorded apply request with: the form is the
// RPC's, a create keys with kind none, and the destroy RPC of a tainted
// replace carries the create envelope and keys with kind id.
// shortcut: the recorder dumps no PriorState, so kind id takes the prior id
// from plan.json change.before.id, the value Core sends as PriorState id.
func applyRequest(t *testing.T, name string, msgpack, typeJSON, envJSON []byte, form instancekey.Form, priorID string) (tftypes.Value, string, any) {
	t.Helper()
	typ, err := tftypes.ParseJSONType(typeJSON) //nolint:staticcheck // the recorded wire form of the schema type
	if err != nil {
		t.Fatalf("%s: type: %v", name, err)
	}
	planned, err := (&tfprotov5.DynamicValue{MsgPack: msgpack}).Unmarshal(typ)
	if err != nil || planned.IsNull() != (form == instancekey.FormDelete) {
		t.Fatalf("%s: PlannedState null %v for form %s (%v)", name, planned.IsNull(), form, err)
	}
	var env struct {
		V   int `json:"v"`
		CTF struct {
			Op                string          `json:"op"`
			PriorIdentity     json.RawMessage `json:"prior_identity"`
			PriorIdentityKind string          `json:"prior_identity_kind"`
		} `json:"ctf"`
	}
	if err = json.Unmarshal(envJSON, &env); err != nil || env.V != 1 {
		t.Fatalf("%s: envelope v %d (%v)", name, env.V, err) // value-free: no prior identity
	}
	kind := env.CTF.PriorIdentityKind
	switch {
	case form == instancekey.FormCreate:
		kind = tfvalue.KindNone
	case form == instancekey.FormDelete && env.CTF.Op == "create" && kind == tfvalue.KindNone:
		kind = tfvalue.KindID
	}
	idType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String}}
	priorState := tftypes.NewValue(idType, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, priorID)})
	prior, err := tfvalue.Prior(kind, env.CTF.PriorIdentity, priorState)
	if err != nil {
		t.Fatalf("%s: prior identity: %v", name, err)
	}
	return planned, kind, prior
}

// priorIDs is change.before.id per address/deposed of a plan.
func priorIDs(t *testing.T, path string) map[string]string {
	t.Helper()
	var plan struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Deposed string `json:"deposed"`
			Change  struct {
				Before struct {
					ID string `json:"id"`
				} `json:"before"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	decodeGolden(t, path, &plan)
	out := map[string]string{}
	for _, rc := range plan.ResourceChanges {
		out[rc.Address+"/"+rc.Deposed] = rc.Change.Before.ID
	}
	return out
}
