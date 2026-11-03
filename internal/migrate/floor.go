package migrate

import (
	"fmt"
	"slices"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/compliancetf/ctfkit/internal/gate"
	"github.com/compliancetf/ctfkit/internal/graph"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
	"github.com/compliancetf/ctfkit/pkg/verdict/resolve"
)

// FloorViolations returns the floor_violations blockers of the unit in dir:
// every graph control of the verified bundles whose decision on the
// pre-migration plan is not pass and blocks under the profile's mode table
// (a deny control under hard_fail, or grandfather, which acts as hard_fail
// until baselines arrive in M3). Each needs remediation or an authorized
// exception before the unit migrates, since the wrapper would fail the
// proof plan on it. ver comes from verdict.VerifyInputs, plan is the show
// -json of the preflight plan; nothing here runs terraform or a network call.
//
// shortcut: resource-local (CEL) controls are not evaluated, as ctfkit has no
// CEL engine, and verified grants are not matched, as ctfkit verifies none yet;
// the proof (PM-T12) stays the fallback for both. Upgrade with the CEL
// evaluator and grant verification.
func FloorViolations(dir string, ver *verdict.Verified, plan *tfjson.Plan, lock *ctfkit.Lockfile) ([]Blocked, error) {
	if ver == nil || ver.Profile == nil {
		return nil, fmt.Errorf("migrate: %s: no verified profile", dir)
	}
	mode, err := gate.ProfileModeTable(ver.Profile)
	if err != nil {
		return nil, fmt.Errorf("migrate: %s: %w", dir, err)
	}
	var controls []graph.Control
	for _, b := range ver.Bundles {
		cs, perr := gate.ParseControls(b.Files[verdict.ControlsFile])
		if perr != nil {
			return nil, fmt.Errorf("migrate: %s: bundle %s: %w", dir, b.Manifest.BundleID, perr)
		}
		for _, c := range cs {
			if c.Kind == gate.KindGraph && c.Graph.Rule == graph.RuleCompanionPresent {
				controls = append(controls, c.Control)
			}
		}
	}
	decided, err := graph.Evaluate(plan, lock, controls)
	if err != nil {
		return nil, fmt.Errorf("migrate: %s: %w", dir, err)
	}
	var out []Blocked
	for _, d := range decided {
		ctl := resolve.Control{ID: d.Control, Version: d.Version, Action: d.Action}
		m := mode.Mode(ctl)
		if d.Result == graph.ResultPass || !resolve.Blocks(m, ctl) {
			continue
		}
		detail := fmt.Sprintf("%s: %s %s %s under floor %s; remediate it or add an authorized exception", d.Address, d.Control, d.Version, d.Result, m)
		if d.Reason != "" {
			detail = fmt.Sprintf("%s: %s %s %s (%s) under floor %s; remediate it or add an authorized exception", d.Address, d.Control, d.Version, d.Result, d.Reason, m)
		}
		if b := (Blocked{Kind: BlockedFloorViolations, Dir: dir, Detail: detail}); !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	sortBlocked(out)
	return out, nil
}
