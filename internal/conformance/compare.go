package conformance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

// Diff returns one line per JSON field that differs between want and got,
// named by its path (runs[0].results[1].level). An unparseable document is a
// single line saying so.
func Diff(want, got []byte) []string {
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		return []string{"recorded document does not parse: " + err.Error()}
	}
	if err := json.Unmarshal(got, &b); err != nil {
		return []string{"adapter document does not parse: " + err.Error()}
	}
	var out []string
	diffValue("", a, b, &out)
	return out
}

func diffValue(path string, a, b any, out *[]string) {
	switch av := a.(type) {
	case map[string]any:
		if bv, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range av {
				keys[k] = true
			}
			for k := range bv {
				keys[k] = true
			}
			sorted := make([]string, 0, len(keys))
			for k := range keys {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			for _, k := range sorted {
				diffValue(join(path, k), av[k], bv[k], out)
			}
			return
		}
	case []any:
		if bv, ok := b.([]any); ok {
			for i := 0; i < max(len(av), len(bv)); i++ {
				var x, y any
				if i < len(av) {
					x = av[i]
				}
				if i < len(bv) {
					y = bv[i]
				}
				diffValue(path+"["+strconv.Itoa(i)+"]", x, y, out)
			}
			return
		}
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, fmt.Sprintf("%s: recorded %s, adapter %s", path, short(a), short(b)))
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func short(v any) string {
	if v == nil {
		return "absent"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(raw) > 120 {
		return string(raw[:117]) + "..."
	}
	return string(raw)
}

// Fields are what the Spacelift summary file carries, and so all that can be
// compared for it.
type Fields struct {
	Verdict   string         `json:"verdict"`
	Watermark string         `json:"watermark"`
	Summary   map[string]int `json:"summary"`
	// Findings are "ruleId level", in document order.
	Findings []string `json:"findings"`
}

// Spacelift projection properties. ToSARIF of the Spacelift adapter records
// the file's own verdict and counts under these keys, so FieldsOf reads what
// the file said instead of recomputing it.
const (
	propVerdict   = "spacelift.verdict"
	propSummary   = "spacelift.summary"
	propWatermark = "ctf.watermark"
)

type sarifDoc struct {
	Runs []struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Results    []struct {
			RuleID       string `json:"ruleId"`
			Level        string `json:"level"`
			Suppressions []struct {
				Status string `json:"status"`
			} `json:"suppressions"`
		} `json:"results"`
	} `json:"runs"`
}

// FieldsOf reads the Spacelift fields of a SARIF document. For a recorded
// document the verdict and counts are derived the way the Spacelift renderer
// derives them: a suppressed result stays in the list and leaves the counts
// and the verdict alone.
func FieldsOf(doc []byte) (Fields, error) {
	var parsed sarifDoc
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return Fields{}, fmt.Errorf("parse SARIF: %w", err)
	}
	if len(parsed.Runs) != 1 {
		return Fields{}, fmt.Errorf("SARIF document has %d runs, want 1", len(parsed.Runs))
	}
	run := parsed.Runs[0]
	f := Fields{Verdict: "pass", Summary: map[string]int{"error": 0, "warning": 0, "note": 0}, Findings: []string{}}
	if err := unmarshalProp(run.Properties, propWatermark, &f.Watermark); err != nil {
		return Fields{}, err
	}
	for _, r := range run.Results {
		f.Findings = append(f.Findings, r.RuleID+" "+r.Level)
		if suppressed(r.Suppressions) {
			continue
		}
		f.Summary[r.Level]++
		if r.Level == "error" {
			f.Verdict = "fail"
		}
	}
	if _, projected := run.Properties[propVerdict]; projected {
		if err := unmarshalProp(run.Properties, propVerdict, &f.Verdict); err != nil {
			return Fields{}, err
		}
		if err := unmarshalProp(run.Properties, propSummary, &f.Summary); err != nil {
			return Fields{}, err
		}
	}
	return f, nil
}

func unmarshalProp(props map[string]json.RawMessage, key string, into any) error {
	raw, ok := props[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("property %s: %w", key, err)
	}
	return nil
}

// suppressed is SARIF's reading of a suppressions array: any entry that is not
// rejected or under review suppresses the result.
func suppressed(entries []struct {
	Status string `json:"status"`
}) bool {
	for _, s := range entries {
		if s.Status != "rejected" && s.Status != "underReview" {
			return true
		}
	}
	return false
}

// DiffFields compares two field sets and names every field that differs.
func DiffFields(want, got Fields) []string {
	a, err := json.Marshal(want)
	if err != nil {
		return []string{err.Error()}
	}
	b, err := json.Marshal(got)
	if err != nil {
		return []string{err.Error()}
	}
	return Diff(a, b)
}
