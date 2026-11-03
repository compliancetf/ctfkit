package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fixtureHome stands in for the canonical absolute input dir in the expected
// plan files, whose local_paths are absolute.
const fixtureHome = "/home/bobthecorp/infra"

// workspaceLists is `workspace list` stdout per fixture and unit dir, in the
// format Terraform 1.16 and OpenTofu 1.13 print (recorded on a local backend).
var workspaceLists = map[string]map[string]string{
	"01-single-root-local":                 {".": "* default\n\n"},
	"02-aliases-and-configuration-aliases": {".": "* default\n\n"},
	"03-local-modules":                     {".": "* default\n\n"},
	"05-implied-provider":                  {".": "* default\n\n"},
	"09-opentofu-host":                     {".": "* default\n\n"},
	"04-remote-module-blocked":             {".": "* default\n\n"},
	"14-tf-json-blocked":                   {".": "* default\n\n"},
	"18-hard-fail-violations":              {".": "* default\n\n"},
	"06-cli-workspaces": {
		"live/app": "* default\n  staging\n  prod\n\n",
		"live/dns": "* default\n\n",
	},
}

// TestDiscoverUnitsFixtures is the PM-T03 oracle: units[] of the expected
// plan of fixtures 01, 03 and 06, of the PM-T04 fixtures 02, 05 and 09 and
// of the PM-T05 fixtures 04, 14 and 18.
func TestDiscoverUnitsFixtures(t *testing.T) {
	for name, lists := range workspaceLists {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "fixtures", "migrate", name)
			input, err := filepath.Abs(filepath.Join(dir, "input"))
			if err == nil {
				input, err = filepath.EvalSymlinks(input)
			}
			if err != nil {
				t.Fatal(err)
			}
			list := func(_ context.Context, u Unit) ([]byte, error) {
				out, ok := lists[u.Dir]
				if !ok {
					return nil, errors.New("unexpected unit " + u.Dir)
				}
				return []byte(out), nil
			}
			got, err := DiscoverUnits(context.Background(), input, list)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if p := got[i].LocalPaths; p != nil {
					p.StatePath = fixturePath(input, p.StatePath)
					p.WorkspaceDir = fixturePath(input, p.WorkspaceDir)
				}
			}

			raw, err := os.ReadFile(filepath.Join(dir, "expected", "migrate-plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want struct {
				Units []Unit `json:"units"`
			}
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want.Units) {
				g, _ := json.MarshalIndent(got, "", "  ")
				w, _ := json.MarshalIndent(want.Units, "", "  ")
				t.Errorf("units:\n%s\nwant:\n%s", g, w)
			}
		})
	}
}

func fixturePath(input, p string) string {
	rel, err := filepath.Rel(input, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return fixtureHome + "/" + filepath.ToSlash(rel)
}

func TestParseWorkspaceList(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "* default\n\n", want: []string{"default"}},
		{in: "  default\n* dev\r\n  prod\n\n", want: []string{"default", "dev", "prod"}},
		{in: "", wantErr: true},
		{in: "\n\n", wantErr: true},
		{in: "default\n", wantErr: true},
		{in: "* \n", wantErr: true},
		{in: "  two words\n", wantErr: true},
		{in: "Warning: The active workspace is being overridden\n", wantErr: true},
		{in: "  default\n  prod\n\n", wantErr: true},
		{in: "* default\n* prod\n\n", wantErr: true},
	}
	for _, tc := range cases {
		got, err := parseWorkspaceList([]byte(tc.in))
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseWorkspaceList(%q) = %v, %v; want %v, err %v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

// TestDiscoverUnitsBackends covers the backend handling no fixture of this
// task reaches: credential names, absolute local paths and refusals.
func TestDiscoverUnitsBackends(t *testing.T) {
	one := func(context.Context, Unit) ([]byte, error) { return []byte("* default\n"), nil }
	cases := []struct {
		name, tf string
		check    func(t *testing.T, u Unit)
		wantErr  string
	}{
		{
			name: "s3",
			tf:   "terraform {\n  backend \"s3\" {\n    bucket  = \"bobthecorp-state\"\n    encrypt = true\n  }\n}\n",
			check: func(t *testing.T, u Unit) {
				if u.Backend != "s3" || u.LocalPaths != nil || !reflect.DeepEqual(u.BackendEnv, backendEnv["s3"]) {
					t.Errorf("unit = %+v", u)
				}
			},
		},
		{
			name: "absolute local path",
			tf:   "terraform {\n  backend \"local\" {\n    path = \"/nonexistent-bobthecorp/app.tfstate\"\n  }\n}\n",
			check: func(t *testing.T, u Unit) {
				if u.LocalPaths == nil || u.LocalPaths.StatePath != filepath.Clean("/nonexistent-bobthecorp/app.tfstate") {
					t.Errorf("local_paths = %+v", u.LocalPaths)
				}
			},
		},
		{name: "cloud", tf: "terraform {\n  cloud {\n    organization = \"bobthecorp\"\n  }\n}\n", wantErr: "HCP/TFE"},
		{name: "remote", tf: "terraform {\n  backend \"remote\" {}\n}\n", wantErr: "HCP/TFE"},
		{name: "unknown", tf: "terraform {\n  backend \"consul\" {}\n}\n", wantErr: "not supported"},
		{name: "unparseable", tf: `terraform {`, wantErr: "does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tc.tf), 0o600); err != nil {
				t.Fatal(err)
			}
			units, err := DiscoverUnits(context.Background(), dir, one)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || len(units) != 1 {
				t.Fatalf("units = %v, err = %v", units, err)
			}
			tc.check(t, units[0])
		})
	}
}

func TestDiscoverUnitsListError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("terraform {\n  backend \"local\" {}\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fail := func(context.Context, Unit) ([]byte, error) { return nil, errors.New("exit status 1") }
	if _, err := DiscoverUnits(context.Background(), dir, fail); err == nil || !strings.Contains(err.Error(), "workspace list") {
		t.Fatalf("err = %v", err)
	}
}

// TestLocalPathsResolveSymlinks: a state path through a symlinked directory is
// recorded at its canonical location, the not-yet-created file kept.
func TestLocalPathsResolveSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	tf := "terraform {\n  backend \"local\" {\n    path          = \"link/app.tfstate\"\n    workspace_dir = \"link/ws\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o600); err != nil {
		t.Fatal(err)
	}
	units, err := DiscoverUnits(context.Background(), dir, func(context.Context, Unit) ([]byte, error) { return []byte("* default\n"), nil })
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(dir, "real"))
	if err != nil {
		t.Fatal(err)
	}
	want := LocalPaths{StatePath: filepath.Join(real, "app.tfstate"), WorkspaceDir: filepath.Join(real, "ws")}
	if got := units[0].LocalPaths; got == nil || *got != want {
		t.Fatalf("local_paths = %+v; want %+v", got, want)
	}
}

// TestLocalPathsDanglingSymlink: a state path through a symlink whose target
// does not exist is refused, not recorded at the link.
func TestLocalPathsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing", "new.tfstate"), filepath.Join(dir, "state.tfstate")); err != nil {
		t.Fatal(err)
	}
	tf := "terraform {\n  backend \"local\" {\n    path = \"state.tfstate\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := DiscoverUnits(context.Background(), dir, func(context.Context, Unit) ([]byte, error) { return []byte("* default\n"), nil })
	if err == nil || !strings.Contains(err.Error(), "dangling symlink") {
		t.Fatalf("err = %v", err)
	}
}
