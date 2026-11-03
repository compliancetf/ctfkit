package receipt

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// TestStatus: the first true condition in table order wins; none is enforced.
func TestStatus(t *testing.T) {
	for _, tc := range []struct {
		conditions []string
		want       string
	}{
		{nil, StatusEnforced},
		{[]string{StatusSingleResourceOnly, StatusEvidenceDegraded}, StatusEvidenceDegraded},
		{[]string{StatusEvidenceDegraded, StatusOverridden}, StatusOverridden},
		{[]string{StatusOverridden, StatusFailed}, StatusFailed},
		{[]string{StatusFailed, StatusRecoveryRequired}, StatusRecoveryRequired},
	} {
		if got := Status(tc.conditions); got != tc.want {
			t.Errorf("Status(%v) = %s, want %s", tc.conditions, got, tc.want)
		}
	}
}

func sampleRun() ProviderRun {
	return ProviderRun{
		Generator: Generator{Name: "ctfkit", Version: "test"},
		Run:       RunInfo{ID: "bobthecorp-run-1", OrgID: "bobthecorp", Workspace: "default", RunnerClass: RunnerCI, Now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)},
		Chains:    []ChainRef{{Chain: "c_1791201600000_0101010101010101"}},
	}
}

// TestRenderProviderRun: conditions listed once each in table order, empty
// lists present, the caller's chains left as given.
func TestRenderProviderRun(t *testing.T) {
	in := sampleRun()
	in.Conditions = []string{StatusEvidenceDegraded, StatusOverridden, StatusEvidenceDegraded}
	raw, err := RenderProviderRun(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind      string `json:"kind"`
		Statement struct {
			Alerts     []string `json:"alerts"`
			Conditions []string `json:"conditions"`
			Chains     []struct {
				Missing []SeqRange `json:"missing"`
			} `json:"chains"`
			Sinks  []SinkRef `json:"sinks"`
			Status string    `json:"status"`
		} `json:"statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Statement
	if doc.Kind != KindProviderRun || s.Status != StatusOverridden ||
		!slices.Equal(s.Conditions, []string{StatusOverridden, StatusEvidenceDegraded}) ||
		s.Alerts == nil || s.Sinks == nil || s.Chains[0].Missing == nil {
		t.Errorf("receipt = %s", raw)
	}
	if in.Chains[0].Missing != nil {
		t.Error("the caller's chains were changed")
	}
}

func TestRenderProviderRunRefuses(t *testing.T) {
	for name, edit := range map[string]func(*ProviderRun){
		"unknown condition": func(p *ProviderRun) { p.Conditions = []string{"partial"} },
		"no run id":         func(p *ProviderRun) { p.Run.ID = "" },
		"no clock":          func(p *ProviderRun) { p.Run.Now = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			in := sampleRun()
			edit(&in)
			if _, err := RenderProviderRun(in); err == nil {
				t.Fatal("rendered")
			}
		})
	}
}
