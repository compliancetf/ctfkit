package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// FixtureClock is the run time every recorded projection was rendered at.
var FixtureClock = time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

// Input builds the AnalyzerInput a runner would build for f, with the
// exported loaders, so the analyzers can be run without a binary.
func Input(f Fixture) (ctfkit.AnalyzerInput, error) {
	in := ctfkit.AnalyzerInput{
		Stage:    f.Stage,
		Metadata: ctfkit.RunMetadata{RunID: FixtureRunID, Commit: FixtureCommit, Platform: "local", Now: FixtureClock},
	}
	var err error
	if in.Config, err = loader.LoadConfig(f.Input); err != nil {
		return in, err
	}
	switch f.Stage {
	case ctfkit.PostInit:
		if in.Modules, err = loader.LoadModules(f.Input); err != nil {
			return in, err
		}
		if f.TestsJSON != "" {
			if in.Modules.Tests, err = loader.ImportTests(f.TestsJSON); err != nil {
				return in, err
			}
		}
	case ctfkit.PostPlan:
		if in.PlanJSON, err = loader.LoadPlan(filepath.Join(f.Input, "plan.json")); err != nil {
			return in, err
		}
	}

	cat := catalog.Embedded()
	if f.CatalogPath != "" {
		if cat, err = catalog.Load(f.CatalogPath); err != nil {
			return in, err
		}
	}
	in.Catalog = cat

	if f.ConfigPath != "" {
		settings, loadErr := config.Load(f.ConfigPath)
		if loadErr != nil {
			return in, loadErr
		}
		in.Settings = settings.Settings()
	}
	return in, nil
}

// CheckPure runs every analyzer twice at once on the same input, with the
// input hashed before and after, and fails on an error, a mutation, or (under
// -race) a data race. It proves purity only for the paths this input
// exercises.
func CheckPure(t testing.TB, analyzers []ctfkit.Analyzer, in ctfkit.AnalyzerInput) {
	t.Helper()
	for _, a := range analyzers {
		before, err := hashInput(in)
		if err != nil {
			t.Fatalf("hash the input: %v", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Go(func() { _, errs[i] = a.Analyze(context.Background(), in) })
		}
		wg.Wait()
		for _, runErr := range errs {
			if runErr != nil {
				t.Errorf("%s: Analyze: %v", a.ID(), runErr)
			}
		}
		after, err := hashInput(in)
		if err != nil {
			t.Fatalf("hash the input: %v", err)
		}
		if after != before {
			t.Errorf("%s at %s mutated its AnalyzerInput", a.ID(), a.Stage())
		}
	}
}

// hashInput hashes everything an analyzer can reach. The catalog has no
// exported fields, so it is hashed through its formatted value, which prints
// maps in key order and holds no pointers. fmt follows a pointer only at the
// top level, so a pointer field added to the catalog would escape this hash.
func hashInput(in ctfkit.AnalyzerInput) ([32]byte, error) {
	body, err := json.Marshal(struct {
		Stage    ctfkit.Stage
		Config   *ctfkit.ConfigArchive
		Modules  *ctfkit.ModuleInventory
		Plan     any
		State    any
		Settings ctfkit.Settings
		Metadata ctfkit.RunMetadata
	}{in.Stage, in.Config, in.Modules, in.PlanJSON, in.State, in.Settings, in.Metadata})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(body, fmt.Sprintf("%+v", in.Catalog)...)), nil
}
