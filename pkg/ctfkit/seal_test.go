package ctfkit_test

import (
	"time"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The seals are meant to be satisfiable from outside this package by an
// implementation that accepts the terms, which is what the loaders and the
// hosted backends do. These fakes prove the escape hatch works; the compile
// time assertions at the bottom are the test.

type fakeCatalog struct {
	ctfkit.CatalogSeal
	modules  []ctfkit.ModuleRef
	controls map[ctfkit.ControlID]ctfkit.ControlRef
}

func (c fakeCatalog) ControlsFor(string) []ctfkit.ControlID { return nil }

func (c fakeCatalog) Control(id ctfkit.ControlID) (ctfkit.ControlRef, bool) {
	ref, ok := c.controls[id]
	return ref, ok
}

func (c fakeCatalog) Frameworks(ctfkit.ControlID) []string        { return nil }
func (c fakeCatalog) Framework(ctfkit.ControlID, string) []string { return nil }
func (c fakeCatalog) Modules() []ctfkit.ModuleRef                 { return c.modules }
func (c fakeCatalog) Hosts() map[string]string                    { return map[string]string{"soc_2": "soc2"} }
func (c fakeCatalog) DefaultHost() string                         { return "soc_2" }
func (c fakeCatalog) Version() ctfkit.CatalogVersion              { return ctfkit.CatalogVersion{} }

func (c fakeCatalog) ModuleFor(resourceType string) (ctfkit.ModuleRef, bool) {
	for _, m := range c.modules {
		for _, rt := range m.ResourceTypes {
			if rt == resourceType {
				return m, true
			}
		}
	}
	return ctfkit.ModuleRef{}, false
}

type fakeExceptions struct {
	ctfkit.ExceptionRegistrySeal
	entries []ctfkit.Exception
}

func (f fakeExceptions) Match(control ctfkit.ControlID, resource string, now time.Time) (ctfkit.Exception, bool) {
	return f.pick(func(e ctfkit.Exception) bool {
		return e.ControlID != "" && e.ControlID == control && e.Resource == resource
	}, now)
}

func (f fakeExceptions) MatchRule(ruleID, resource string, now time.Time) (ctfkit.Exception, bool) {
	return f.pick(func(e ctfkit.Exception) bool {
		return e.RuleID != "" && e.RuleID == ruleID && e.Resource == resource
	}, now)
}

// pick returns the first valid entry in scope, or the first entry of that
// scope when none is valid, which is what the interface promises.
func (f fakeExceptions) pick(inScope func(ctfkit.Exception) bool, now time.Time) (ctfkit.Exception, bool) {
	var first ctfkit.Exception
	found := false
	for _, e := range f.entries {
		if !inScope(e) {
			continue
		}
		if f.IsValid(e, now) {
			return e, true
		}
		if !found {
			first, found = e, true
		}
	}
	return first, found
}

func (f fakeExceptions) IsValid(e ctfkit.Exception, now time.Time) bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	d := e.ExpiresAt.UTC()
	endOfDay := time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, time.UTC)
	return !now.UTC().After(endOfDay)
}

var (
	_ ctfkit.ControlCatalog    = fakeCatalog{}
	_ ctfkit.ExceptionRegistry = fakeExceptions{}
	_ ctfkit.Registry          = ctfkit.NewRegistry()
)
