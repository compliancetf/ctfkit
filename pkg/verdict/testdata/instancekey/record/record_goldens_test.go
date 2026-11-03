//go:build record

// The apply recording driver of the instance_key goldens. ctfkit
// scripts/record-instancekey-apply.sh copies this file into the
// internal/proxy directory of a clean terraform-provider-aws checkout, runs
// it with the record build tag and deletes it again; Go never builds it in
// ctfkit (testdata). For each golden type it sends the plan and apply RPCs of
// every managed change of plan.json, typed by schema.json, through the proxy
// in front of the in-process fake upstream (startRoute), in the order and
// shape Terraform Core sends them. The proxy stamps the plan envelope itself
// (prior_identity_kind included) and its record build tag
// (internal/proxy/record_on.go) dumps each apply request; this driver only
// renames the dumps from <type>.<hash> to the resource address and form, and
// writes SOURCE.json. No real provider, no cloud, no Terraform binary.

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

type goldenChange struct {
	Address      string `json:"address"`
	Deposed      string `json:"deposed"`
	Mode         string `json:"mode"`
	ActionReason string `json:"action_reason"`
	Change       struct {
		Actions        []string `json:"actions"`
		After          any      `json:"after"`
		AfterUnknown   any      `json:"after_unknown"`
		Before         any      `json:"before"`
		BeforeIdentity any      `json:"before_identity"`
	} `json:"change"`
}

type goldenRecord struct {
	Address string            `json:"address"`
	Deposed string            `json:"deposed,omitempty"`
	Form    string            `json:"form"`
	Name    string            `json:"recorded_name"`
	SHA256  map[string]string `json:"sha256"`
}

type goldenSource struct {
	Comment        string            `json:"comment"`
	ProviderCommit string            `json:"provider_commit"`
	Recorder       map[string]string `json:"recorder_sha256"`
	Records        []goldenRecord    `json:"records"`
}

const goldenComment = "Apply requests dumped by the terraform-provider-aws record build tag " +
	"(internal/proxy/record_on.go) at provider_commit, driven from plan.json and schema.json " +
	"by record/record_goldens_test.go (scripts/record-instancekey-apply.sh) through an in-process " +
	"fake upstream. form is the apply RPC's: create (null prior), update, delete (null planned). " +
	"Map keys are in sorted order, as Core's cty encoding writes them."

var goldenAddress = regexp.MustCompile(`^[a-z0-9_]+\.[a-z0-9_]+$`)

func TestRecordGoldens(t *testing.T) {
	gold, out, commit := os.Getenv("CTFKIT_GOLDEN_DIR"), os.Getenv("CTFKIT_RECORD_OUT"), os.Getenv("CTFKIT_PROVIDER_COMMIT")
	if gold == "" || out == "" || commit == "" {
		t.Skip("run by ctfkit scripts/record-instancekey-apply.sh")
	}
	src := goldenSource{Comment: goldenComment, ProviderCommit: commit, Recorder: map[string]string{
		"internal/proxy/record_on.go":   goldenSum(t, "record_on.go"),
		"record/record_goldens_test.go": goldenSum(t, "zz_record_goldens_test.go"),
	}}
	for _, typ := range strings.Fields(os.Getenv("CTFKIT_GOLDEN_TYPES")) {
		t.Run(typ, func(t *testing.T) { recordGolden(t, filepath.Join(gold, typ), filepath.Join(out, typ), typ, src) })
	}
}

func recordGolden(t *testing.T, dir, dest, typ string, src goldenSource) {
	block, identity := goldenSchema(t, filepath.Join(dir, "schema.json"), typ)
	resType := goldenBlockType(t, block)
	raw := t.TempDir()
	t.Setenv("COMPLIANCETF_RECORD_DIR", raw)
	client, up, _ := startRoute(t, hook.Noop{})
	up.schema = &tfplugin5.GetProviderSchema_Response{ResourceSchemas: map[string]*tfplugin5.Schema{typ: {Block: goldenProtoBlock(t, block)}}}
	warmSchema(t, client)
	ctx := context.Background()

	enc := func(typ tftypes.Type, v tftypes.Value) *tfplugin5.DynamicValue {
		dv, err := tfprotov5.NewDynamicValue(typ, v)
		if err != nil {
			t.Fatal(err)
		}
		return &tfplugin5.DynamicValue{Msgpack: goldenCanon(t, dv.MsgPack)}
	}
	planRPC := func(prior, planned *tfplugin5.DynamicValue, id *tfplugin5.ResourceIdentityData, priorPrivate []byte, replace bool) []byte {
		up.plan = &tfplugin5.PlanResourceChange_Response{PlannedState: planned}
		if replace {
			up.plan.RequiresReplace = []*tfplugin5.AttributePath{{Steps: []*tfplugin5.AttributePath_Step{{Selector: &tfplugin5.AttributePath_Step_AttributeName{AttributeName: "id"}}}}}
		}
		resp, err := client.PlanResourceChange(ctx, &tfplugin5.PlanResourceChange_Request{
			TypeName: typ, PriorState: prior, ProposedNewState: planned, Config: planned, PriorIdentity: id, PriorPrivate: priorPrivate,
		})
		if err != nil || hasErrorDiag(resp.Diagnostics) {
			t.Fatalf("plan: %v %v", err, resp.GetDiagnostics())
		}
		return resp.PlannedPrivate
	}

	var plan struct {
		ResourceChanges []goldenChange `json:"resource_changes"`
	}
	goldenDecode(t, filepath.Join(dir, "plan.json"), &plan)
	for _, sub := range []string{"apply", "envelope"} {
		if err := os.MkdirAll(filepath.Join(dest, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, rc := range plan.ResourceChanges {
		a := rc.Change.Actions
		if rc.Mode != "managed" || (len(a) == 1 && (a[0] == "no-op" || a[0] == "read") && rc.Deposed == "") {
			continue
		}
		if !goldenAddress.MatchString(rc.Address) {
			t.Fatalf("address %q is not a plain file name", rc.Address)
		}
		null := enc(resType, tftypes.NewValue(resType, nil))
		before, after := null, null
		if rc.Change.Before != nil {
			before = enc(resType, goldenValue(t, resType, rc.Change.Before, nil))
		}
		if rc.Change.After != nil {
			after = enc(resType, goldenValue(t, resType, rc.Change.After, rc.Change.AfterUnknown))
		}
		var id *tfplugin5.ResourceIdentityData // what Core sends as prior and destroy identity
		if rc.Change.BeforeIdentity != nil && identity == nil {
			t.Fatalf("%s: before_identity without an identity schema for %s", rc.Address, typ)
		}
		if rc.Change.BeforeIdentity != nil {
			id = &tfplugin5.ResourceIdentityData{IdentityData: enc(identity, goldenValue(t, identity, rc.Change.BeforeIdentity, nil))}
		}
		apply := func(form string, prior, planned *tfplugin5.DynamicValue, pp []byte, id *tfplugin5.ResourceIdentityData) {
			up.apply = &tfplugin5.ApplyResourceChange_Response{NewState: planned}
			resp, err := client.ApplyResourceChange(ctx, &tfplugin5.ApplyResourceChange_Request{
				TypeName: typ, PriorState: prior, PlannedState: planned, Config: planned, PlannedPrivate: pp, PlannedIdentity: id,
			})
			if err != nil || hasErrorDiag(resp.Diagnostics) {
				t.Fatalf("%s %s apply: %v %v", rc.Address, form, err, resp.GetDiagnostics())
			}
			sum := sha256.Sum256(append(append(append([]byte{}, prior.Msgpack...), 0), planned.Msgpack...))
			name := typ + "." + hex.EncodeToString(sum[:8])
			base := rc.Address
			if rc.Deposed != "" {
				base += "." + rc.Deposed
			}
			base += "." + form
			r := goldenRecord{Address: rc.Address, Deposed: rc.Deposed, Form: form, Name: name, SHA256: map[string]string{}}
			for _, f := range [][2]string{
				{"apply/" + name + ".msgpack", "apply/" + base + ".msgpack"},
				{"apply/" + name + ".type.json", "apply/" + base + ".type.json"},
				{"envelope/" + name + ".json", "envelope/" + base + ".json"},
			} {
				if err := os.Rename(filepath.Join(raw, f[0]), filepath.Join(dest, f[1])); err != nil {
					t.Fatalf("recorder wrote no %s: %v", f[0], err)
				}
				r.SHA256[f[1]] = goldenSum(t, filepath.Join(dest, f[1]))
			}
			tj, err := os.ReadFile(filepath.Join(dest, "apply", base+".type.json"))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := tftypes.ParseJSONType(tj); err != nil || !got.Equal(resType) { //nolint:staticcheck // the recorded wire form
				t.Fatalf("%s: proxy schema type differs from schema.json (%v)", base, err)
			}
			src.Records = append(src.Records, r)
		}
		switch strings.Join(a, ",") {
		case "create":
			apply("create", null, after, planRPC(null, after, nil, nil, false), nil)
		case "update":
			apply("update", before, after, planRPC(before, after, id, nil, false), id)
		case "delete":
			apply("delete", before, null, planRPC(before, null, id, nil, false), id)
		case "delete,create", "create,delete":
			// Core plans the change, re-plans the create half with a null
			// prior and the first plan's private, and sends the re-plan's
			// private to both apply RPCs. A tainted object is planned as a
			// create only, and both RPCs carry that create envelope.
			var pp []byte
			if rc.ActionReason == "replace_because_tainted" {
				pp = planRPC(null, after, nil, nil, false)
			} else {
				pp = planRPC(null, after, nil, planRPC(before, after, id, nil, true), false)
			}
			halves := []func(){func() { apply("delete", before, null, pp, id) }, func() { apply("create", null, after, pp, nil) }}
			if a[0] == "create" {
				slices.Reverse(halves)
			}
			for _, h := range halves {
				h()
			}
		default:
			t.Fatalf("%s: actions %v", rc.Address, a)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(raw, "*", "*")); len(left) != 0 {
		t.Fatalf("unexpected recordings %v", left)
	}
	b, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SOURCE.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// goldenCanon is msgpack b with every map's entries sorted by key. tftypes
// writes map entries in Go map order, so its bytes differ between runs; Core
// (cty) writes them sorted, as object attributes already are.
func goldenCanon(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := goldenCanonValue(msgpack.NewDecoder(bytes.NewReader(b)), &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func goldenCanonValue(dec *msgpack.Decoder, out *bytes.Buffer) error {
	c, err := dec.PeekCode()
	if err != nil {
		return err
	}
	switch {
	case msgpcode.IsFixedMap(c) || c == msgpcode.Map16 || c == msgpcode.Map32:
		n, err := dec.DecodeMapLen()
		if err != nil {
			return err
		}
		type entry struct {
			key string
			raw []byte
		}
		entries := make([]entry, n)
		for i := range entries {
			var e bytes.Buffer
			k, err := dec.DecodeRaw()
			if err != nil {
				return err
			}
			if err := msgpack.Unmarshal(k, &entries[i].key); err != nil {
				return err
			}
			e.Write(k)
			if err := goldenCanonValue(dec, &e); err != nil {
				return err
			}
			entries[i].raw = e.Bytes()
		}
		slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.key, b.key) })
		if err := msgpack.NewEncoder(out).EncodeMapLen(n); err != nil {
			return err
		}
		for _, e := range entries {
			out.Write(e.raw)
		}
	case msgpcode.IsFixedArray(c) || c == msgpcode.Array16 || c == msgpcode.Array32:
		n, err := dec.DecodeArrayLen()
		if err != nil {
			return err
		}
		if err := msgpack.NewEncoder(out).EncodeArrayLen(n); err != nil {
			return err
		}
		for range n {
			if err := goldenCanonValue(dec, out); err != nil {
				return err
			}
		}
	default:
		raw, err := dec.DecodeRaw()
		if err != nil {
			return err
		}
		out.Write(raw)
	}
	return nil
}

func goldenSum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func goldenDecode(t *testing.T, path string, v any) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

type goldenBlock struct {
	Attributes map[string]struct {
		Type      json.RawMessage `json:"type"`
		Required  bool            `json:"required"`
		Optional  bool            `json:"optional"`
		Computed  bool            `json:"computed"`
		Sensitive bool            `json:"sensitive"`
	} `json:"attributes"`
	BlockTypes map[string]struct {
		Block       goldenBlock `json:"block"`
		NestingMode string      `json:"nesting_mode"`
	} `json:"block_types"`
}

// goldenSchema is typ's block and identity type (nil without one) in a
// terraform providers schema -json file.
func goldenSchema(t *testing.T, path, typ string) (goldenBlock, tftypes.Type) {
	t.Helper()
	var s struct {
		ProviderSchemas map[string]struct {
			Resources map[string]struct {
				Block goldenBlock `json:"block"`
			} `json:"resource_schemas"`
			Identities map[string]struct {
				Attributes map[string]struct {
					Type json.RawMessage `json:"type"`
				} `json:"attributes"`
			} `json:"resource_identity_schemas"`
		} `json:"provider_schemas"`
	}
	goldenDecode(t, path, &s)
	for _, ps := range s.ProviderSchemas {
		r, ok := ps.Resources[typ]
		if !ok {
			continue
		}
		id, ok := ps.Identities[typ]
		if !ok {
			return r.Block, nil
		}
		attrs := map[string]tftypes.Type{}
		for n, a := range id.Attributes {
			attrs[n] = goldenCtyType(t, a.Type)
		}
		return r.Block, tftypes.Object{AttributeTypes: attrs}
	}
	t.Fatalf("%s: no schema for %s", path, typ)
	return goldenBlock{}, nil
}

func goldenCtyType(t *testing.T, raw json.RawMessage) tftypes.Type {
	t.Helper()
	typ, err := tftypes.ParseJSONType(raw) //nolint:staticcheck // the cty JSON type syntax of the schema file
	if err != nil {
		t.Fatal(err)
	}
	return typ
}

var goldenNesting = map[string]tfplugin5.Schema_NestedBlock_NestingMode{
	"single": tfplugin5.Schema_NestedBlock_SINGLE, "list": tfplugin5.Schema_NestedBlock_LIST, "set": tfplugin5.Schema_NestedBlock_SET,
	"map": tfplugin5.Schema_NestedBlock_MAP, "group": tfplugin5.Schema_NestedBlock_GROUP,
}

// goldenProtoBlock is b as the upstream serves it in GetSchema.
func goldenProtoBlock(t *testing.T, b goldenBlock) *tfplugin5.Schema_Block {
	t.Helper()
	out := &tfplugin5.Schema_Block{}
	for _, n := range slices.Sorted(maps.Keys(b.Attributes)) {
		a := b.Attributes[n]
		if len(a.Type) == 0 {
			t.Fatalf("attribute %s: nested_type has no protocol 5 form", n)
		}
		out.Attributes = append(out.Attributes, &tfplugin5.Schema_Attribute{Name: n, Type: a.Type, Required: a.Required, Optional: a.Optional, Computed: a.Computed, Sensitive: a.Sensitive})
	}
	for _, n := range slices.Sorted(maps.Keys(b.BlockTypes)) {
		bt := b.BlockTypes[n]
		mode, ok := goldenNesting[bt.NestingMode]
		if !ok {
			t.Fatalf("block %s: nesting %q", n, bt.NestingMode)
		}
		out.BlockTypes = append(out.BlockTypes, &tfplugin5.Schema_NestedBlock{TypeName: n, Nesting: mode, Block: goldenProtoBlock(t, bt.Block)})
	}
	return out
}

func goldenBlockType(t *testing.T, b goldenBlock) tftypes.Type {
	t.Helper()
	attrs := map[string]tftypes.Type{}
	for n, a := range b.Attributes {
		attrs[n] = goldenCtyType(t, a.Type)
	}
	for n, bt := range b.BlockTypes {
		o := goldenBlockType(t, bt.Block)
		switch bt.NestingMode {
		case "list":
			o = tftypes.List{ElementType: o}
		case "set":
			o = tftypes.Set{ElementType: o}
		case "map":
			o = tftypes.Map{ElementType: o}
		}
		attrs[n] = o
	}
	return tftypes.Object{AttributeTypes: attrs}
}

func goldenDynamic(t tftypes.Type) bool {
	switch t := t.(type) {
	case tftypes.List:
		return goldenDynamic(t.ElementType)
	case tftypes.Set:
		return goldenDynamic(t.ElementType)
	case tftypes.Map:
		return goldenDynamic(t.ElementType)
	case tftypes.Tuple:
		return slices.ContainsFunc(t.ElementTypes, goldenDynamic)
	}
	return t.Is(tftypes.DynamicPseudoType)
}

// goldenValue is the tftypes value of plan JSON j with after_unknown u, as
// Core holds it before encoding PlannedState or PriorState. u is nil, a bool
// or the shape of the value; anything else fails the recording.
func goldenValue(t *testing.T, typ tftypes.Type, j, u any) tftypes.Value {
	t.Helper()
	if u == true {
		return tftypes.NewValue(typ, tftypes.UnknownValue)
	}
	if typ.Is(tftypes.DynamicPseudoType) {
		t.Fatal("dynamic attribute: no aws golden type has one; add it here when one does")
	}
	if u == false {
		u = nil
	}
	um, isMap := u.(map[string]any)
	ul, isList := u.([]any)
	bad := func() { t.Fatalf("after_unknown %T for a %s value", u, typ) }
	switch typ.(type) {
	case tftypes.Object, tftypes.Map:
		if u != nil && !isMap {
			bad()
		}
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		if u != nil && !isList {
			bad()
		}
	default:
		if u != nil {
			bad()
		}
	}
	if j == nil || goldenDynamic(typ) {
		return tftypes.NewValue(typ, nil) // the key omits a dynamic-bearing value
	}
	switch tt := typ.(type) {
	case tftypes.Object:
		vals := map[string]tftypes.Value{}
		for n, a := range tt.AttributeTypes {
			vals[n] = goldenValue(t, a, j.(map[string]any)[n], um[n])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.Map:
		vals := map[string]tftypes.Value{}
		for k, e := range j.(map[string]any) {
			vals[k] = goldenValue(t, tt.ElementType, e, um[k])
		}
		return tftypes.NewValue(tt, vals)
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		var vals []tftypes.Value
		for i, e := range j.([]any) {
			var et tftypes.Type
			switch tt := tt.(type) {
			case tftypes.List:
				et = tt.ElementType
			case tftypes.Set:
				et = tt.ElementType
			case tftypes.Tuple:
				et = tt.ElementTypes[i]
			}
			var eu any
			if i < len(ul) {
				eu = ul[i]
			}
			vals = append(vals, goldenValue(t, et, e, eu))
		}
		return tftypes.NewValue(tt, vals)
	}
	if n, ok := j.(json.Number); ok {
		f, _, err := big.ParseFloat(n.String(), 10, 512, big.ToNearestEven)
		if err != nil {
			t.Fatalf("number %s: %v", n, err)
		}
		return tftypes.NewValue(typ, f)
	}
	return tftypes.NewValue(typ, j)
}
