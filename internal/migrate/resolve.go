package migrate

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

// BlockedNoWrapperRelease: no compliancetf release equals the upstream
// version the unit's lockfile resolves.
const BlockedNoWrapperRelease = "no_wrapper_release"

// stableVersion is an X.Y.Z release: upstream versions and the compliancetf
// releases that proxy them. Prereleases (X.Y.Z-beta.N, X.Y.Z-compliancetf.N)
// never equal an upstream version and are not offered as nearest.
var stableVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// ResolveWrapper returns the providers[] entry of the wrapped type typ for a
// unit in dir whose lockfile resolves hashicorp/<typ> to the upstream version
// u. Version parity: compliancetf/<typ> X.Y.Z proxies hashicorp/<typ> X.Y.Z,
// so the wrapper version W is u itself, and the lockfile entry is exact u.
// The root and module constraints are only written where an entry has none.
// releases are the versions registry.compliance.tf lists for compliancetf/<typ>.
//
// When no release equals u, the unit is blocked (no_wrapper_release) with the
// nearest stable releases and the action. The detail holds only versions that
// match stableVersion, so a registry answer cannot carry text into blocked[].
func ResolveWrapper(dir, typ, u string, releases []string) (Provider, *Blocked, error) {
	uv, ok := parseStable(u)
	if !ok {
		return Provider{}, nil, fmt.Errorf("migrate: %s: hashicorp/%s lockfile version is not X.Y.Z", dir, typ)
	}
	if slices.Contains(releases, u) {
		return Provider{
			Type:             typ,
			From:             "registry.terraform.io/hashicorp/" + typ,
			To:               "registry.compliance.tf/compliancetf/" + typ,
			UpstreamVersion:  u,
			WrapperVersion:   u,
			RootConstraint:   fmt.Sprintf("~> %d.%d", uv[0], uv[1]),
			ModuleConstraint: fmt.Sprintf(">= %d.0.0", uv[0]),
		}, nil, nil
	}

	var below, above string // nearest stable releases under and over u
	var bv, av [3]int
	for _, r := range releases {
		rv, ok := parseStable(r)
		if !ok {
			continue
		}
		switch c := cmpVersion(rv, uv); {
		case c < 0 && (below == "" || cmpVersion(rv, bv) > 0):
			below, bv = r, rv
		case c > 0 && (above == "" || cmpVersion(rv, av) < 0):
			above, av = r, rv
		}
	}
	head := fmt.Sprintf("no compliancetf/%s release runs hashicorp/%s %s", typ, typ, u)
	var detail string
	switch {
	case below == "" && above == "":
		detail = fmt.Sprintf("%s (none published); wait for the release of %s", head, u)
	case below == "":
		detail = fmt.Sprintf("%s (nearest: %s, the first release); upgrade hashicorp/%s to >= %s", head, above, typ, above)
	case above == "":
		detail = fmt.Sprintf("%s (nearest: %s, the latest release); wait for the release of %s", head, below, u)
	default:
		detail = fmt.Sprintf("%s (nearest: %s, %s); upgrade hashicorp/%s to %s or wait for the release of %s", head, below, above, typ, above, u)
	}
	return Provider{}, &Blocked{Kind: BlockedNoWrapperRelease, Dir: dir, Detail: detail}, nil
}

func parseStable(v string) ([3]int, bool) {
	m := stableVersion.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1]) // the regex bounds each part to 9 digits
	}
	return out, true
}

func cmpVersion(a, b [3]int) int {
	return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]), cmp.Compare(a[2], b[2]))
}
