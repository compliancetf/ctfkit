package modulesource

import "strings"

// classification is the row of the module-source table a source falls in.
// Only three of the rows emit a finding; the other three are the shape of the
// silence, and they are named so that a reader of this package can see that
// the silence was decided rather than forgotten.
type classification int

const (
	// classIgnored is a source that is not a module registry address at all:
	// a local path, a forced getter such as git:: or s3::, or a plain URL to
	// an archive. Where it comes from is ctf.origin.catalog's and
	// ctf.policy.floating_ref's subject, not this rule's, and the recorded
	// fixture 04-floating-ref carries no module_source result for its
	// git::https:// source.
	classIgnored classification = iota
	// classServed is a compliance.tf endpoint, intact. The configuration is
	// already on the served module, so there is nothing to report.
	classServed
	// classServedDisabled is a compliance.tf endpoint carrying a disable
	// query. The finding belongs to ctf.policy.disabled_control, which is
	// what the recorded fixture 03-ctf-module-disabled-control carries, so
	// this analyzer stays quiet rather than emitting a second result about
	// the same module call.
	classServedDisabled
	// classUpstream is an upstream terraform-aws-modules registry address.
	// The same path is served under the organization's framework host, which
	// makes it a migration candidate.
	classUpstream
	// classThirdParty is any other registry address. No compliance.tf module
	// replaces it, so it is listed for inventory and nothing is suggested.
	classThirdParty
	// classUnknownRegistry is a registry address whose host the endpoint
	// allowlist does not name.
	classUnknownRegistry
)

// upstreamNamespace is the registry namespace compliance.tf serves. A module
// in it has the same path under a framework host.
const upstreamNamespace = "terraform-aws-modules"

// complianceSuffix is the domain every served endpoint sits under. It is the
// fallback classification, used when the settings file names no endpoint
// allowlist.
const complianceSuffix = ".compliance.tf"

// publicRegistryHosts are the two public module registries. A source that
// names one is the same address as the one that omits it, so the host is
// dropped and the namespace decides the row. Without this an ordinary
// registry.terraform.io/terraform-aws-modules/... source would be reported as
// an unknown private registry.
var publicRegistryHosts = map[string]bool{
	"registry.terraform.io": true,
	"registry.opentofu.org": true,
}

// source is one module source, read far enough to classify it. Nothing here
// resolves or fetches anything: it is string work over what the configuration
// or the plan document already says.
type source struct {
	// class is the row of the classification table.
	class classification
	// host is the registry host, empty for a hostless registry address and
	// for a source that is not a registry address.
	host string
	// path is the registry address with the host and any query removed, for
	// example "terraform-aws-modules/iam/aws//modules/iam-policy". It is what
	// goes under a framework host to form the remediation.
	path string
}

// classify reads a module source string and says which row it falls in.
//
// endpoints is the settings-file allowlist. It replaces the compliance.tf
// suffix rule wholesale when it is set: an organization that names its
// endpoints has said which hosts are served, and a host outside that list is
// an unknown registry even when it ends in compliance.tf. An empty allowlist
// falls back to the suffix, which is what an unconfigured repository gets.
func classify(raw string, endpoints []string) source {
	s := strings.TrimSpace(raw)
	if s == "" || isLocalPath(s) || hasForcedGetter(s) {
		return source{class: classIgnored}
	}

	// Terraform reads a scheme-qualified source as an HTTP archive, never as a
	// registry address. The one scheme-qualified form this rule classifies is
	// a compliance.tf endpoint written as a URL, which the recorded fixture
	// 03-ctf-module-disabled-control carries; every other URL is an archive
	// and is left to the origin rules, even when its path happens to have
	// three segments.
	unschemed := strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	hasScheme := unschemed != s
	s = unschemed

	// Everything after '#' is a URL fragment that the getter never sends, so
	// it must not decide the host: "https://evil.example#.compliance.tf/..."
	// fetches from evil.example.
	s, _, _ = strings.Cut(s, "#")

	query := ""
	if i := strings.IndexByte(s, '?'); i >= 0 {
		query, s = s[i+1:], s[:i]
	}

	addr, submodule, hasSubmodule := strings.Cut(s, "//")
	segments := strings.Split(strings.TrimSuffix(addr, "/"), "/")

	host := ""
	if len(segments) == 4 && isHost(segments[0]) {
		host, segments = segments[0], segments[1:]
	}
	if publicRegistryHosts[strings.ToLower(host)] {
		host = ""
	}
	if len(segments) != 3 {
		// Not ns/name/provider, so not a registry address. An archive URL and
		// a mistyped source both land here and are left to the origin rules.
		return source{class: classIgnored}
	}

	path := strings.Join(segments, "/")
	if hasSubmodule {
		path += "//" + submodule
	}

	if hasScheme && (host == "" || !isServedHost(host, endpoints)) {
		return source{class: classIgnored}
	}
	if host != "" {
		return source{class: hostClass(host, endpoints, query), host: host, path: path}
	}
	// Registry namespaces are case-insensitive.
	if strings.EqualFold(segments[0], upstreamNamespace) {
		return source{class: classUpstream, path: path}
	}

	return source{class: classThirdParty, path: path}
}

// EndpointAllowed reports whether a module source may be installed under the
// endpoint allowlist, with the same reading of endpoints as the
// module-source rule: a ./ or ../ path, which is code of the package that
// calls it, or a registry address on a served endpoint, a disable query
// included. Anything else is not allowed: another registry host, the public
// registry, a forced getter such as git::, an archive URL, an absolute path
// (which go-getter copies like a remote) and an empty source.
func EndpointAllowed(raw string, endpoints []string) bool {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		return true
	}
	switch classify(s, endpoints).class {
	case classServed, classServedDisabled:
		return true
	default:
		return false
	}
}

// hostClass decides the row of a registry address that names a host.
func hostClass(host string, endpoints []string, query string) classification {
	if !isServedHost(host, endpoints) {
		return classUnknownRegistry
	}
	if hasDisableParameter(query) {
		return classServedDisabled
	}

	return classServed
}

// isServedHost reports whether host is a compliance.tf endpoint.
func isServedHost(host string, endpoints []string) bool {
	host = strings.ToLower(host)
	if len(endpoints) > 0 {
		for _, endpoint := range endpoints {
			if normalizeEndpoint(endpoint) == host {
				return true
			}
		}

		return false
	}

	return strings.HasSuffix(host, complianceSuffix) || host == strings.TrimPrefix(complianceSuffix, ".")
}

// normalizeEndpoint reduces an allowlist entry to the bare host, so that
// "https://soc2.compliance.tf/" and "soc2.compliance.tf" are one entry.
func normalizeEndpoint(entry string) string {
	e := strings.ToLower(strings.TrimSpace(entry))
	e = strings.TrimPrefix(strings.TrimPrefix(e, "https://"), "http://")

	return strings.Trim(e, "/")
}

// hasDisableParameter reports whether the source query switches a control off.
func hasDisableParameter(query string) bool {
	for _, parameter := range strings.Split(query, "&") {
		if strings.HasPrefix(parameter, "disable=") {
			return true
		}
	}

	return false
}

// isLocalPath reports whether the source is a path on disk rather than an
// address.
func isLocalPath(s string) bool {
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/")
}

// hasForcedGetter reports whether the source carries a Terraform forced
// getter prefix such as "git::" or "s3::", which always names a remote
// archive or repository rather than a registry module.
func hasForcedGetter(s string) bool {
	i := strings.Index(s, "::")
	if i < 0 {
		return false
	}
	slash := strings.IndexByte(s, '/')

	return slash < 0 || i < slash
}

// isHost reports whether a leading segment is a registry host rather than a
// namespace. A namespace carries neither a dot nor a port.
func isHost(segment string) bool {
	return strings.ContainsAny(segment, ".:")
}
