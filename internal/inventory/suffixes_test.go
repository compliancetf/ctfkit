package inventory_test

import (
	"path/filepath"
	"testing"

	"github.com/compliancetf/ctfkit/internal/inventory"
	"github.com/compliancetf/ctfkit/internal/loader"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// A root that declares its resources in any of the four configuration
// suffixes counts them; the local module's resource is its own and is not
// counted.
func TestRootResourcesCountEverySuffix(t *testing.T) {
	for _, dir := range []string{"tf", "tofu", "tf-json", "tofu-json"} {
		t.Run(dir, func(t *testing.T) {
			config, err := loader.LoadConfig(filepath.Join("..", "..", "testdata", "postplan_json", dir))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			got, err := inventory.Build(&ctfkit.ModuleInventory{}, config)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got.RootResources.Declared != 2 || got.RootResources.Coverage != inventory.CoverageUnattested {
				t.Errorf("RootResources = %+v, want 2 declared, unattested", got.RootResources)
			}
		})
	}
}
