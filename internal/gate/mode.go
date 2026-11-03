package gate

import (
	"encoding/json"
	"fmt"

	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// ModeFloor is the mode_floor member of a signed org profile.
type ModeFloor struct {
	Default      string            `json:"default"`
	Environments map[string]string `json:"environments"`
}

var modeRank = map[string]int{resolve.Advisory: 0, resolve.SoftFail: 1, resolve.Grandfather: 2, resolve.HardFail: 3}

func maxMode(a, b string) string {
	ra, okA := modeRank[a]
	rb, okB := modeRank[b]
	switch {
	case !okB && b != "":
		return resolve.HardFail // an unknown floor fails closed
	case !okA || rb > ra:
		return b
	}
	return a
}

// ModeTable mirrors the provider's run mode with a profile: soft_fail, the
// default floor and the environment floor (the profile's fixed environment,
// else the strongest environment floor: an asserted environment is never
// trusted to weaken it). HCL and env enforcement modes may only raise it at
// apply, where the provider resolves again.
func ModeTable(floor ModeFloor, controlFloors map[string]string, environment string) resolve.ModeTable {
	m := maxMode(resolve.SoftFail, floor.Default)
	if environment != "" {
		m = maxMode(m, floor.Environments[environment])
	} else {
		for _, f := range floor.Environments {
			m = maxMode(m, f)
		}
	}
	return resolve.ModeTable{RunMode: m, ControlFloors: controlFloors}
}

// ProfileModeTable is ModeTable of a verified profile, read from its
// mode_floor, control_floors and scope.environment members.
func ProfileModeTable(p *verdict.Profile) (resolve.ModeTable, error) {
	var (
		floor  ModeFloor
		floors map[string]string
		scope  struct {
			Environment string `json:"environment"`
		}
	)
	for _, m := range []struct {
		name string
		raw  json.RawMessage
		v    any
	}{{"mode_floor", p.ModeFloor, &floor}, {"control_floors", p.ControlFloors, &floors}, {"scope", p.Scope, &scope}} {
		if len(m.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(m.raw, m.v); err != nil {
			return resolve.ModeTable{}, fmt.Errorf("profile %s: %w", m.name, err)
		}
	}
	return ModeTable(floor, floors, scope.Environment), nil
}
