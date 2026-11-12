package pack

import (
	"fmt"
	"strings"
)

// Values a cell reads when there is nothing to show.
const (
	none   = "None"
	notSet = "Not set"
)

// RenderMarkdown renders pack.md.
func RenderMarkdown(p *Pack) (File, error) {
	var b strings.Builder
	names := map[string]string{}
	for _, fw := range p.Frameworks {
		names[fw.ID] = fw.Name
	}
	fwName := func(id string) string {
		if n := names[id]; n != "" {
			return n
		}
		return id
	}

	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# Compliance evidence pack\n\n")
	w("**%s** This pack records what ctfkit by compliance.tf read from the module manifests "+
		"installed by `terraform init`. compliance.tf does not sign, attest or verify it.\n\n", Notice)
	w("| | |\n|---|---|\n")
	w("| Release | %s |\n", cell(p.Release.Name))
	w("| Commit | %s |\n", orNotSet(code(p.Release.Commit)))
	w("| Generated | %s by %s %s |\n", cell(p.GeneratedAt), cell(p.Generator.Name), cell(p.Generator.Version))
	w("| Control catalog | %s, %s |\n", cell(p.Catalog.Version), catalogSource(p.Catalog))
	fws := make([]string, 0, len(p.Frameworks))
	for _, fw := range p.Frameworks {
		fws = append(fws, fw.Name)
	}
	w("| Frameworks | %s |\n\n", cell(strings.Join(fws, ", ")))

	w("## 1 Summary\n\n")
	w("Counts are taken from the module manifests and the control catalog named above.\n\n")
	s := p.Summary
	w("| | |\n|---|---|\n")
	w("| Modules in scope | %d, %d with a compliance.tf manifest |\n", s.Modules, s.ModulesWithManifest)
	w("| Controls enforced | %d |\n", s.ControlsEnforced)
	w("| Controls delegated to another scope | %d |\n", s.ControlsDelegated)
	for _, fc := range s.PerFramework {
		w("| With a %s clause | %d of %d |\n", cell(fwName(fc.Framework)), fc.WithClause, fc.Of)
	}
	w("| Framework gaps with a recorded reason | %d of %d |\n", s.NoClauseWithReason, s.NoClause)
	w("| Catalog controls for these resource types not enforced here | %d |\n", s.NotEnforced)
	w("| Control enforcement tests | %s |\n", testSummary(p.Tests))
	w("| Findings at error level | %s |\n\n", count(s.FindingsAtError))

	w("## 2 Scope\n\n")
	w("The modules `terraform init` installed for this release. A module without a compliance.tf manifest is listed in the report findings.\n\n")
	if len(p.Scope) == 0 {
		w("%s.\n\n", none)
	} else {
		w("| Module | Source | Version | Manifest sha256 |\n|---|---|---|---|\n")
		for _, m := range p.Scope {
			sha := none
			switch {
			case m.ManifestSHA256 != "":
				sha = code(m.ManifestSHA256)
			case m.DeclaresNoResources:
				sha = none + ", declares no resources"
			}
			w("| %s | %s | %s | %s |\n", code(m.Key), code(m.Source), cell(m.Version), sha)
		}
		w("\n")
	}

	w("## 3 What this pack shows, and what it does not\n\n")
	w("It shows:\n\n")
	for _, line := range p.Shows {
		w("- %s\n", line)
	}
	w("\nIt does not show:\n\n")
	for _, line := range p.DoesNotShow {
		w("- %s\n", line)
	}
	w("\n")

	w("## 4 Control-to-clause mapping\n\n")
	w("Every control each module manifest lists, with the clauses it gives evidence for. " +
		"A clause marked (supporting) is partial or indirect evidence. " +
		"None means no clause in that framework; section 5 gives the reason. Clause titles are in annex A.\n\n")
	if len(p.Mapping) == 0 {
		w("%s.\n\n", none)
	}
	for _, mm := range p.Mapping {
		w("### Module %s\n\n", code(mm.Module))
		w("| Control | Status |")
		for _, fw := range mm.Frameworks {
			w(" %s |", cell(fwName(fw)))
		}
		w("\n|---|---|%s\n", strings.Repeat("---|", len(mm.Frameworks)))
		for _, mc := range mm.Controls {
			w("| %s %s | %s |", code(mc.ID), cell(mc.Name), cell(mc.Status))
			for _, fc := range mc.Clauses {
				w(" %s |", clauses(fc.Clauses))
			}
			w("\n")
		}
		w("\n")
	}

	w("## 5 Controls with no clause in a framework\n\n")
	w("A control can have no matching clause in a framework. The reason comes from the control catalog.\n\n")
	if len(p.NoClause) == 0 {
		w("%s.\n\n", none)
	} else {
		for _, nc := range p.NoClause {
			w("- %s %s\n", code(nc.ID), cell(nc.Name))
			for _, f := range nc.Frameworks {
				w("  - %s: %s\n", cell(fwName(f.Framework)), orNotSet(cell(f.Reason)))
			}
		}
		w("\n")
	}

	w("## 6 Catalog controls not enforced by these modules\n\n")
	w("Controls the catalog lists for the resource types of these modules that no module manifest lists, and the layer that owns each one.")
	if p.Catalog.EmbeddedSubset {
		w(" The catalog is the embedded one, which holds the CIS v6.0 controls only, so this list is not complete.")
	}
	w("\n\n")
	if len(p.NotEnforced) == 0 {
		w("%s.\n\n", none)
	} else {
		w("| Control | Resource types | Layer | Reason |\n|---|---|---|---|\n")
		for _, ne := range p.NotEnforced {
			reason := orNotSet(cell(ne.Reason))
			if ne.SupersededBy != "" {
				reason += " Replaced in this build by " + code(ne.SupersededBy) + "."
			}
			w("| %s %s | %s | %s | %s |\n", code(ne.ID), cell(ne.Name), codes(ne.ResourceTypes), orNotSet(cell(ne.Layer)), reason)
		}
		w("\n")
	}

	w("## 7 Enforcement tests\n\n")
	if !p.Tests.Supplied {
		w("No tests supplied. Pass `--tests-json` to `ctfkit report` to include the results of `tofu test -json` or `terraform test -json`.\n\n")
	} else {
		t := p.Tests
		w("Results read from %s (sha256 %s): %s.\n\n", code(t.File), code(t.SHA256), testSummary(t))
		if len(t.Cases) > 0 {
			w("| Test | Module | Result |\n|---|---|---|\n")
			for _, c := range t.Cases {
				w("| %s | %s | %s |\n", code(c.Name), orNotSet(code(c.ModuleKey)), cell(c.Status))
			}
			w("\n")
		}
	}

	w("## Annex A Clause register\n\n")
	w("Every clause cited in this pack, as the module manifests name it, and the clauses the catalog records no control applies to.\n\n")
	if len(p.Register) == 0 {
		w("%s.\n\n", none)
	}
	for _, rf := range p.Register {
		w("### %s\n\n", cell(rf.Name))
		if len(rf.Clauses) == 0 {
			w("%s.\n\n", none)
		} else {
			w("| Clause | Title | Controls |\n|---|---|---|\n")
			for _, c := range rf.Clauses {
				w("| %s | %s | %s |\n", cell(c.ID), orNotSet(cell(c.Title)), codes(c.Controls))
			}
			w("\n")
		}
		w("Clauses with no applicable control: ")
		if len(rf.NotApplicable) == 0 {
			w("%s.\n\n", none)
		} else {
			w("\n\n| Clause | Reason |\n|---|---|\n")
			for _, c := range rf.NotApplicable {
				w("| %s | %s |\n", cell(c.ID), orNotSet(cell(c.Reason)))
			}
			w("\n")
		}
	}

	w("---\n\n%s\n", Notice)
	return File{Name: FileMarkdown, Body: []byte(b.String())}, nil
}

func catalogSource(c Catalog) string {
	switch {
	case c.EmbeddedSubset:
		return "the catalog embedded in ctfkit, which holds the CIS v6.0 controls only; `ctfkit catalog pull` fetches the full catalog"
	case c.Source == SourceHome:
		return "the catalog file at `~/.ctf/control-requirements.yaml`, which `ctfkit catalog pull` writes"
	case c.Source == SourceFile:
		return "the catalog file named with `--catalog`"
	case c.Source == SourceEmbedded:
		return "the catalog embedded in ctfkit"
	}
	return notSet
}

func testSummary(t Tests) string {
	if !t.Supplied {
		return "No tests supplied"
	}
	return fmt.Sprintf("%d runs: %d passed, %d failed, %d errored, %d skipped", t.Runs, t.Passed, t.Failed, t.Errored, t.Skipped)
}

func clauses(refs []ClauseRef) string {
	if len(refs) == 0 {
		return none + " (see 5)"
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		s := cell(r.ID)
		if r.Supporting {
			s += " (supporting)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func count(n int) string {
	if n == 0 {
		return none
	}
	return fmt.Sprint(n)
}

func orNotSet(s string) string {
	if s == "" {
		return notSet
	}
	return s
}

// cell makes text safe inside a table cell or list item.
func cell(s string) string {
	if s == "" {
		return notSet
	}
	return strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ").Replace(s)
}

// code renders a value as inline code; empty reads "" so a caller can fall
// back.
func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + strings.NewReplacer("`", "'", "|", `\|`, "\n", " ").Replace(s) + "`"
}

func codes(list []string) string {
	if len(list) == 0 {
		return none
	}
	parts := make([]string, 0, len(list))
	for _, s := range list {
		parts = append(parts, code(s))
	}
	return strings.Join(parts, ", ")
}
