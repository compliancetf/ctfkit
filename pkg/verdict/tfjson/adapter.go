// Package tfjson is the plan-side adapter of the instance_key format
// (pkg/verdict/testdata/instancekey/FORMAT.md, spec B2): it reads plan JSON
// and provider schema JSON from their raw bytes, numbers as decimal text
// (json.Decoder.UseNumber, never float64), and builds for every key the value
// tree, unknown paths and prior identity that instancekey.Compute hashes.
package tfjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/compliancetf/ctfkit/pkg/verdict/instancekey"
	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// Prior identity kinds (FORMAT.md Forms, fields and prior identity).
const (
	KindIdentity = "identity"
	KindID       = "id"
	KindNone     = "none"
)

// taintedReplace is the action_reason of a tainted replace. Its destroy half
// always keys with kind id, whatever before_identity holds (FORMAT.md prior
// identity rule 1): OpenTofu emits a non-null before_identity for a tainted
// object and the provider keys that RPC with kind id.
const taintedReplace = "replace_because_tainted"

// KeyInput is one key of an instance: Compute's arguments and the result.
type KeyInput struct {
	Field             string // instance_key or delete_key
	Form              instancekey.Form
	PriorIdentityKind string
	Type              string
	Schema            *instancekey.Type
	After             any        // the planned value; nil for delete
	UnknownPaths      [][]string // normalized; empty for delete
	Prior             any        // nil, the identity object, or {"id": id}
	Key               string
}

// Instance is one managed resource change. Err is set, and Keys is empty,
// when the format refuses the instance: gate sign then exits 2.
type Instance struct {
	Address      string
	Deposed      string
	Type         string
	Actions      []string
	ActionReason string
	Keys         []KeyInput
	Err          error
}

// forms is the actions table: the key forms of an action list, in order.
var forms = map[string][]instancekey.Form{
	`["create"]`:          {instancekey.FormCreate},
	`["update"]`:          {instancekey.FormUpdate},
	`["delete"]`:          {instancekey.FormDelete},
	`["delete","create"]`: {instancekey.FormDelete, instancekey.FormCreate},
	`["create","delete"]`: {instancekey.FormCreate, instancekey.FormDelete},
}

// Instances computes the keys of every managed change of a plan, in plan
// order, with the leaf key of the run. A no-op or read change gets no entry
// unless it is deposed (then it is refused). An error is returned when the
// plan as a whole is refused: not strict JSON (duplicate key, invalid UTF-8,
// lone surrogate), not an object, or a resource_changes that is not an array.
// An absent or null resource_changes is a plan with no changes (Terraform
// omits the member when it is empty).
func Instances(leaf [32]byte, plan []byte, schemas *Schemas) ([]Instance, error) {
	doc, err := decodeStrict(plan)
	if err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("plan JSON: not an object")
	}
	rcs, ok := m["resource_changes"].([]any)
	if !ok && m["resource_changes"] != nil {
		return nil, errors.New("plan JSON: resource_changes is not an array")
	}
	var out []Instance
	for _, r := range rcs {
		rc, ok := r.(map[string]any)
		if !ok {
			return nil, errors.New("plan JSON: a resource change is not an object")
		}
		if rc["mode"] != "managed" {
			continue
		}
		inst := Instance{}
		inst.Address, _ = rc["address"].(string)
		inst.Deposed, _ = rc["deposed"].(string)
		inst.Type, _ = rc["type"].(string)
		inst.ActionReason, _ = rc["action_reason"].(string)
		change, _ := rc["change"].(map[string]any)
		actions, aerr := stringList(change["actions"])
		inst.Actions = actions
		noop := slices.Equal(actions, []string{"no-op"}) || slices.Equal(actions, []string{"read"})
		if aerr == nil && noop && inst.Deposed == "" {
			continue
		}
		if aerr != nil {
			inst.Err = aerr
		} else {
			provider, _ := rc["provider_name"].(string)
			inst.Keys, inst.Err = instanceKeys(leaf, &inst, provider, change, schemas)
		}
		if inst.Err != nil {
			inst.Keys = nil
		}
		out = append(out, inst)
	}
	return out, nil
}

func instanceKeys(leaf [32]byte, inst *Instance, provider string, change map[string]any, schemas *Schemas) ([]KeyInput, error) {
	res, ident, err := schemas.resource(provider, inst.Type)
	if err != nil {
		return nil, err
	}
	actions, _ := jsonText(inst.Actions)
	fs, ok := forms[actions]
	if !ok {
		return nil, fmt.Errorf("unsupported actions %s", actions)
	}
	if inst.Deposed != "" && actions != `["delete"]` {
		return nil, errors.New("a deposed object takes only a delete entry")
	}
	var keys []KeyInput
	for _, f := range fs {
		k := KeyInput{Field: "instance_key", Form: f, PriorIdentityKind: KindNone, Type: inst.Type, Schema: res, UnknownPaths: [][]string{}}
		if f == instancekey.FormDelete {
			k.Field = "delete_key"
		} else {
			after, ok := change["after"].(map[string]any)
			if !ok {
				return nil, errors.New("planned after is not an object")
			}
			if k.UnknownPaths, err = unknownPaths(change["after_unknown"], res); err != nil {
				return nil, err
			}
			k.After = after
		}
		if f != instancekey.FormCreate {
			forceID := f == instancekey.FormDelete && inst.ActionReason == taintedReplace
			if k.PriorIdentityKind, k.Prior, err = priorIdentity(change, ident, forceID); err != nil {
				return nil, err
			}
		}
		if k.Key, err = k.Compute(leaf); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Compute is the key of k under the leaf key.
func (k KeyInput) Compute(leaf [32]byte) (string, error) {
	return instancekey.Compute(leaf, k.Type, k.Form, k.Schema, k.After, k.UnknownPaths, k.Prior)
}

// priorIdentity chooses the prior identity kind of an update or delete:
// identity when before_identity, typed by the identity schema, keeps a leaf;
// else id from a non-empty string before.id.
func priorIdentity(change map[string]any, ident *instancekey.Type, forceID bool) (string, any, error) {
	before, ok := change["before"].(map[string]any)
	if !ok && change["before"] != nil {
		return "", nil, errors.New("before is not an object")
	}
	bi, ok := change["before_identity"].(map[string]any)
	if !ok && change["before_identity"] != nil {
		return "", nil, errors.New("before_identity is not an object")
	}
	if bi != nil && ident != nil && !forceID {
		tree, err := identityTree(bi, ident)
		if err != nil {
			return "", nil, fmt.Errorf("before_identity: %w", err)
		}
		if hasLeaf(tree) {
			return KindIdentity, tree, nil
		}
	}
	id, ok := before["id"].(string)
	if !ok || id == "" {
		return "", nil, errors.New("no usable prior identity and no non-empty prior id")
	}
	return KindID, map[string]any{"id": id}, nil
}

// identityTree checks v against the identity type and drops its
// dynamic-bearing members, which the format omits. Compute hashes the result
// untyped, so a set (whose elements Compute would not sort) is refused.
func identityTree(v any, t *instancekey.Type) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch t.Kind {
	case instancekey.Object, instancekey.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("expected an object")
		}
		out := make(map[string]any, len(m))
		for k, e := range m {
			et := t.Elem
			if t.Kind == instancekey.Object {
				if et, ok = t.Attrs[k]; !ok {
					return nil, fmt.Errorf("attribute %q not in schema", k)
				}
				if dynamicBearing(et) {
					continue
				}
			}
			n, err := identityTree(e, et)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = n
		}
		return out, nil
	case instancekey.List, instancekey.Tuple:
		a, ok := v.([]any)
		if !ok || t.Kind == instancekey.Tuple && len(a) != len(t.Elems) {
			return nil, errors.New("expected an array of the schema's length")
		}
		out := make([]any, len(a))
		for i, e := range a {
			et := t.Elem
			if t.Kind == instancekey.Tuple {
				et = t.Elems[i]
			}
			n, err := identityTree(e, et)
			if err != nil {
				return nil, fmt.Errorf("%d: %w", i, err)
			}
			out[i] = n
		}
		return out, nil
	case instancekey.String:
		if _, ok := v.(string); ok {
			return v, nil
		}
	case instancekey.Number:
		if _, ok := v.(json.Number); ok {
			return v, nil
		}
	case instancekey.Bool:
		if _, ok := v.(bool); ok {
			return v, nil
		}
	case instancekey.Set:
		return nil, errors.New("a set in an identity is not supported")
	}
	return nil, errors.New("value does not match its schema type")
}

func hasLeaf(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case map[string]any:
		for _, e := range v {
			if hasLeaf(e) {
				return true
			}
		}
		return false
	case []any:
		return slices.ContainsFunc(v, hasLeaf)
	}
	return true
}

func dynamicBearing(t *instancekey.Type) bool {
	switch t.Kind {
	case instancekey.Dynamic:
		return true
	case instancekey.List, instancekey.Set, instancekey.Map:
		return dynamicBearing(t.Elem)
	case instancekey.Tuple:
		return slices.ContainsFunc(t.Elems, dynamicBearing)
	}
	return false
}

// unknownPaths reads after_unknown against the schema and normalizes it
// (FORMAT.md Unknown values): set paths for any unknown inside a set, no path
// into a dynamic value, no path under a listed prefix, deduplicated and
// sorted by the JCS bytes of each path.
func unknownPaths(u any, t *instancekey.Type) ([][]string, error) {
	if u == true {
		return nil, errors.New("whole planned value unknown")
	}
	if err := checkUnknown(u, t, nil); err != nil {
		return nil, err
	}
	var raw [][]string
	if err := collectUnknown(u, t, nil, &raw); err != nil {
		return nil, err
	}
	byJCS := map[string][]string{}
	for _, p := range raw {
		b, err := jsonText(p)
		if err != nil {
			return nil, err
		}
		byJCS[b] = p
	}
	keys := make([]string, 0, len(byJCS))
	for k := range byJCS {
		keys = append(keys, k)
	}
	slices.Sort(keys) // Go strings compare bytewise
	out := [][]string{}
	for _, k := range keys {
		p := byJCS[k]
		covered := false
		for i := range len(p) {
			q, err := jsonText(p[:i])
			if err != nil {
				return nil, err
			}
			if _, covered = byJCS[q]; covered {
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out, nil
}

// checkUnknown validates every after_unknown marker against the schema; a
// dynamic-bearing node's markers are dropped unread.
func checkUnknown(u any, t *instancekey.Type, path []string) error {
	if u == nil || u == true || u == false || dynamicBearing(t) {
		return nil
	}
	switch v := u.(type) {
	case []any:
		if t.Kind == instancekey.List || t.Kind == instancekey.Set || t.Kind == instancekey.Tuple {
			for i, e := range v {
				et, err := child(t, strconv.Itoa(i))
				if err != nil {
					return err
				}
				if err := checkUnknown(e, et, append(path, strconv.Itoa(i))); err != nil {
					return err
				}
			}
			return nil
		}
	case map[string]any:
		if t.Kind == instancekey.Object || t.Kind == instancekey.Map {
			for k, e := range v {
				et, err := child(t, k)
				if err != nil {
					return err
				}
				if err := checkUnknown(e, et, append(path, k)); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return fmt.Errorf("after_unknown shape does not match the schema at %q", path)
}

// collectUnknown appends the path of every unknown, stopping at a set.
func collectUnknown(u any, t *instancekey.Type, path []string, out *[][]string) error {
	if u == nil || u == false || dynamicBearing(t) {
		return nil
	}
	if t.Kind == instancekey.Set {
		found, err := anyTrue(u)
		if found {
			*out = append(*out, slices.Clone(path))
		}
		return err
	}
	if u == true {
		*out = append(*out, slices.Clone(path))
		return nil
	}
	var steps []string
	var elems []any
	switch v := u.(type) {
	case []any:
		for i, e := range v {
			steps, elems = append(steps, strconv.Itoa(i)), append(elems, e)
		}
	case map[string]any:
		for k, e := range v {
			steps, elems = append(steps, k), append(elems, e)
		}
	default:
		return fmt.Errorf("after_unknown holds %T at %q", u, path)
	}
	for i, step := range steps {
		et, err := child(t, step)
		if err != nil {
			return err
		}
		if err := collectUnknown(elems[i], et, append(slices.Clone(path), step), out); err != nil {
			return err
		}
	}
	return nil
}

// anyTrue reports a true marker anywhere under u, dynamic members included.
// It reads the whole tree before answering, so a bad marker is refused
// whatever the map iteration order.
func anyTrue(u any) (bool, error) {
	var elems []any
	switch v := u.(type) {
	case nil:
		return false, nil
	case bool:
		return v, nil
	case []any:
		elems = v
	case map[string]any:
		for _, e := range v {
			elems = append(elems, e)
		}
	default:
		return false, fmt.Errorf("after_unknown holds %T", u)
	}
	found := false
	for _, e := range elems {
		t, err := anyTrue(e)
		if err != nil {
			return false, err
		}
		found = found || t
	}
	return found, nil
}

// child is the schema type one step below t.
func child(t *instancekey.Type, step string) (*instancekey.Type, error) {
	switch t.Kind {
	case instancekey.Object:
		if a, ok := t.Attrs[step]; ok {
			return a, nil
		}
		return nil, fmt.Errorf("attribute %q not in schema", step)
	case instancekey.List, instancekey.Set, instancekey.Map:
		return t.Elem, nil
	case instancekey.Tuple:
		if i, err := strconv.Atoi(step); err == nil && i >= 0 && i < len(t.Elems) {
			return t.Elems[i], nil
		}
		return nil, fmt.Errorf("tuple index %q out of range", step)
	}
	return nil, fmt.Errorf("cannot step into a scalar with %q", step)
}

func stringList(v any) ([]string, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, errors.New("actions is not an array")
	}
	out := make([]string, len(a))
	for i, e := range a {
		if out[i], ok = e.(string); !ok {
			return nil, errors.New("actions holds a non-string")
		}
	}
	return out, nil
}

// jsonText is the JCS text of a string list.
func jsonText(p []string) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	b, err = jcs.Transform(b)
	return string(b), err
}
