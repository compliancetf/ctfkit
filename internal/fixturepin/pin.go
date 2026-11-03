// Package fixturepin pins the report fixture pack (testdata/fixtures/report):
// the PIN.json format, the offline check the pack is held to, the transforms
// that derive the synthesized cases, the raw-bytes scanner, and the steps
// scripts/record-report-fixtures.sh runs to re-record the pack. Nothing here
// touches the network.
package fixturepin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// PinFile is the pin's file name, at the root of the report pack.
const PinFile = "PIN.json"

// PinFormat is the only pin_format this package reads.
const PinFormat = 1

// Case roles.
const (
	RoleRecorded    = "recorded"
	RoleSynthesized = "synthesized"
)

// Pin is PIN.json. Field order is the canonical (sorted) key order.
type Pin struct {
	Cases        map[string]Case `json:"cases"`
	PinFormat    int             `json:"pin_format"`
	RecordedOn   string          `json:"recorded_on"`
	RegistryHost string          `json:"registry_host"`
	TofuVersion  string          `json:"tofu_version"`
}

// Case is one case directory of the pack.
type Case struct {
	BaseCase  string   `json:"base_case,omitempty"`
	Modules   []Module `json:"modules"`
	Role      string   `json:"role"`
	Transform string   `json:"transform,omitempty"`
}

// Module is one registry module of a case's modules.json. The root entry and
// local sources (./ and ../) are not pinned: the registry did not serve them.
type Module struct {
	Key                   string `json:"key"`
	ManifestSchemaVersion string `json:"manifest_schema_version"`
	ManifestSHA256        string `json:"manifest_sha256"`
	Source                string `json:"source"`
	Version               string `json:"version"`
}

// ReadPin reads and strictly decodes a pin.
func ReadPin(file string) (*Pin, []byte, error) {
	raw, err := os.ReadFile(file) //nolint:gosec // a path the maintainer or the test names
	if err != nil {
		return nil, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Pin
	if err = dec.Decode(&p); err != nil {
		return nil, raw, fmt.Errorf("%s: %w", file, err)
	}
	return &p, raw, nil
}

// Encode is the canonical form: keys sorted, no insignificant whitespace, no
// HTML escaping, no trailing newline, modules in key order.
func (p *Pin) Encode() ([]byte, error) {
	for name, c := range p.Cases {
		sort.Slice(c.Modules, func(i, j int) bool { return c.Modules[i].Key < c.Modules[j].Key })
		p.Cases[name] = c
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

var (
	hostRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	registryRE  = regexp.MustCompile(`^([^/]+)/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/([a-z0-9]{1,64})(//(.+))?$`)
	subdirSegRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	caseNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	dateRE      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	versionRE   = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
)

// ValidHost reports whether host is a lower-case DNS name with at least one dot.
func ValidHost(host string) bool { return hostRE.MatchString(host) }

// ValidCaseName reports whether name is usable as a case directory name.
func ValidCaseName(name string) bool { return caseNameRE.MatchString(name) }

// IsLocalSource reports whether a module source is a path in the
// configuration rather than something fetched.
func IsLocalSource(source string) bool {
	return strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}

// RegistrySource checks source against the registry grammar
// host/namespace/name/system with an optional contained //subdir, on host.
// It returns the package address (the source without //subdir).
func RegistrySource(source, host string) (string, error) {
	m := registryRE.FindStringSubmatch(source)
	if m == nil {
		return "", fmt.Errorf("source %q is not host/namespace/name/system[//subdir]", source)
	}
	if m[1] != host {
		return "", fmt.Errorf("source %q is not on the pinned registry host %s", source, host)
	}
	if m[6] != "" {
		for _, seg := range strings.Split(m[6], "/") {
			if !subdirSegRE.MatchString(seg) || seg == ".." {
				return "", fmt.Errorf("source %q has a //subdir that is not a contained relative path", source)
			}
		}
		if path.Clean(m[6]) != m[6] {
			return "", fmt.Errorf("source %q has a //subdir that is not clean", source)
		}
	}
	return strings.Join(m[1:5], "/"), nil
}
