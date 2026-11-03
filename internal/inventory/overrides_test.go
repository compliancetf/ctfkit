package inventory_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Override files change blocks the primary files declare and never add one,
// and OpenTofu reads storage.tofu instead of its storage.tf twin, so the root
// declares logs, jobs and archive: 3, not the 6 blocks its files hold.
func TestRootResourcesSkipOverridesAndShadowedTwins(t *testing.T) {
	for _, syntax := range []string{"native", "json"} {
		t.Run(syntax, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "testdata", "override_twins", syntax))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			got, err := inventory.Build(&ctfkit.ModuleInventory{}, config)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got.RootResources.Declared != 3 {
				t.Errorf("Declared = %d, want 3", got.RootResources.Declared)
			}
		})
	}
}
