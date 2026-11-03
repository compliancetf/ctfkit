package resolve

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/pkg/verdict"
)

type tableCase struct {
	Description string      `json:"description"`
	Decisions   Decisions   `json:"decisions"`
	Mode        ModeTable   `json:"mode"`
	Exceptions  []Exception `json:"exceptions"`
	Baselines   []Baseline  `json:"baselines"`
	Receipts    []Receipt   `json:"receipts"`
	Want        Outcome     `json:"want"`
}

func decodeStrict(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// TestTable runs testdata/*.json, the resolver table (B10), and checks the
// table covers every state in every mode and every exemption kind.
func TestTable(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.json")
	if len(files) < 30 {
		t.Fatalf("%d resolver fixtures", len(files))
	}
	seen := map[string]bool{}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			var c tableCase
			decodeStrict(t, f, &c)
			got := Resolve(c.Decisions, c.Mode, c.Exceptions, c.Baselines, c.Receipts)
			if !reflect.DeepEqual(got, c.Want) {
				g, _ := json.MarshalIndent(got, "", "  ")
				t.Fatalf("%s\ngot  %s", c.Description, g)
			}
			for _, r := range got.Rows {
				seen[c.Mode.RunMode+"/"+r.State] = true
				seen[r.Result] = true
				if r.Proof != nil {
					seen["proof/"+r.Proof.Kind] = true
				}
			}
		})
	}
	var want []string
	for _, m := range []string{Advisory, SoftFail, Grandfather, HardFail} {
		for _, s := range []string{StatePass, StateFail, StateNotEvaluable, StateProvisional, StatePending} {
			want = append(want, m+"/"+s)
		}
	}
	want = append(want, ResultExcepted, ResultUnproven, ResultMissing, ResultUnknownType, ResultInvalidHalf,
		"proof/"+KindGrant, "proof/"+KindSelfService, "proof/"+KindBaseline, "proof/"+KindBreakGlass)
	for _, w := range want {
		if !seen[w] {
			t.Errorf("no fixture covers %s", w)
		}
	}
}

// TestNotEvaluableIsFail: not_evaluable resolves exactly as fail in every
// mode, for every action and coverable list, with and without a receipt.
func TestNotEvaluableIsFail(t *testing.T) {
	r := Receipt{Digest: "sha256:r", OverrideID: "o", Controls: []string{"c"}, ActionKeys: []string{"k"}}
	for _, m := range []string{"", Advisory, SoftFail, Grandfather, HardFail} {
		for _, action := range []string{"deny", "warn"} {
			for _, cov := range [][]string{nil, {KindBreakGlass}} {
				for _, listed := range [][]string{nil, {r.Digest}} {
					res := func(state string) Row {
						in := Decisions{
							Instances: []verdict.Instance{{Address: "fake_thing.a", Type: "fake_thing", Action: "update", InstanceKey: "k",
								Decisions: []verdict.Decision{{Control: "c", Version: "1", Result: state}}, BreakGlass: listed}},
							Required: map[string]Halves{"fake_thing": {Decisions: []Control{{ID: "c", Version: "1", Action: action, Coverable: cov}}}},
						}
						return Resolve(in, ModeTable{RunMode: m}, nil, nil, []Receipt{r}).Rows[0]
					}
					f, n := res(StateFail), res(StateNotEvaluable)
					if f.Severity != n.Severity || f.Final != n.Final || !reflect.DeepEqual(f.Proof, n.Proof) {
						t.Errorf("mode %q action %s coverable %v listed %v: fail %+v, not_evaluable %+v", m, action, cov, listed, f, n)
					}
				}
			}
		}
	}
}

// situationCase is the provider's internal/verdict situation golden
// (testdata/provider/situations, copied verbatim).
type situationCase struct {
	Delete  bool               `json:"delete"`
	Type    string             `json:"type"`
	Matches []verdict.Instance `json:"matches"`
	Graph   []struct {
		ID           string `json:"id"`
		Version      string `json:"version"`
		FailSeverity string `json:"fail_severity"`
	} `json:"graph"`
	Excepted []string `json:"excepted"`
	Want     []struct {
		Control  string `json:"control"`
		Version  string `json:"version"`
		Result   string `json:"result"`
		Severity string `json:"severity"`
	} `json:"want"`
}

// modeFor is a (mode, action) whose apply_pre fail row is sev.
var modeFor = map[string]string{SevError: HardFail, SevWarning: SoftFail, SevNone: Advisory}

// resolve runs one situation case through Resolve: each graph control's
// fail severity becomes a control floor, each excepted control a grant
// listed for the match.
func (c situationCase) resolve(t *testing.T) []Row {
	t.Helper()
	if len(c.Matches) != 1 {
		t.Fatalf("%d matches: Resolve decides one entry", len(c.Matches))
	}
	m := c.Matches[0]
	mode := ModeTable{RunMode: Advisory, ControlFloors: map[string]string{}}
	var ctls []Control
	for _, g := range c.Graph {
		mode.ControlFloors[g.ID] = modeFor[g.FailSeverity]
		ctls = append(ctls, Control{ID: g.ID, Version: g.Version, Action: "deny", Coverable: []string{KindGrant}})
	}
	var ex []Exception
	for _, id := range c.Excepted {
		d := "sha256:grant-" + id
		ex = append(ex, Exception{Digest: d, Kind: KindGrant, Controls: []string{id}})
		m.Exceptions = append(m.Exceptions, d)
	}
	half, h := HalfCreate, Halves{Decisions: ctls}
	if c.Delete {
		half, h = HalfDelete, Halves{DeleteDecisions: ctls}
	}
	in := Decisions{Instances: []verdict.Instance{m}, Required: map[string]Halves{c.Type: h}, Half: half}
	return Resolve(in, mode, ex, nil, nil).Rows
}

// TestProviderSituations cross-checks Resolve against the provider's
// situation goldens of decided rows: same control, result and severity.
func TestProviderSituations(t *testing.T) {
	files, _ := filepath.Glob("testdata/provider/situations/*.json")
	if len(files) < 13 {
		t.Fatalf("%d provider situation goldens", len(files))
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			var c situationCase
			b, err := os.ReadFile(f)
			if err == nil {
				err = json.Unmarshal(b, &c)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := c.resolve(t)
			if len(got) != len(c.Want) {
				t.Fatalf("rows %+v, want %+v", got, c.Want)
			}
			for i, w := range c.Want {
				g := got[i]
				if g.Control != w.Control || g.Version != w.Version || g.Result != w.Result || g.Severity != w.Severity {
					t.Errorf("row %d: %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

// TestProviderFailClosed cross-checks the provider's fail-closed goldens
// missing-decision and exemption-no-proof: the evidence situation and a
// blocking decision.
func TestProviderFailClosed(t *testing.T) {
	type golden struct {
		Apply struct {
			Evidence struct {
				Results []struct {
					Control, Version, Decision, Situation string
				} `json:"results"`
			} `json:"evidence"`
		} `json:"apply"`
		Situation   *situationCase `json:"situation"`
		Eligibility *struct {
			Coverable []string `json:"coverable"`
		} `json:"eligibility"`
		Address string `json:"address"`
	}
	for _, name := range []string{"missing-decision", "exemption-no-proof"} {
		t.Run(name, func(t *testing.T) {
			var g golden
			b, err := os.ReadFile(filepath.Join("testdata", "provider", "failclosed", name+".json"))
			if err == nil {
				err = json.Unmarshal(b, &g)
			}
			if err != nil {
				t.Fatal(err)
			}
			res := g.Apply.Evidence.Results
			var got []Row
			if g.Situation != nil {
				got = g.Situation.resolve(t)
			} else { // a provisional decision with no proof listed
				in := Decisions{Required: map[string]Halves{"fake_thing": {}}}
				h := in.Required["fake_thing"]
				inst := verdict.Instance{Address: g.Address, Type: "fake_thing", Action: "create", Refreshed: "true"}
				for _, r := range res {
					h.Decisions = append(h.Decisions, Control{ID: r.Control, Version: r.Version, Action: "deny", Coverable: g.Eligibility.Coverable})
					inst.Decisions = append(inst.Decisions, verdict.Decision{Control: r.Control, Version: r.Version, Result: StateProvisional})
				}
				in.Required["fake_thing"], in.Instances = h, []verdict.Instance{inst}
				got = Resolve(in, ModeTable{RunMode: HardFail}, nil, nil, nil).Rows
			}
			if len(got) != len(res) {
				t.Fatalf("rows %+v, want %+v", got, res)
			}
			for i, r := range res {
				if got[i].Control != r.Control || got[i].Result != r.Situation || got[i].Severity != SevError || r.Decision != "blocked" {
					t.Errorf("row %d: %+v, want %+v blocked", i, got[i], r)
				}
			}
		})
	}
}
