// Package codeexec implements the ctf.exec rules: code a configuration would
// run on the machine that plans or applies it, found before plan runs any of
// it (docs/threat-model.md, threat A3).
//
//   - ctf.exec.provisioner: a provisioner block, local-exec, remote-exec or
//     file alike, in a resource or removed block.
//   - ctf.exec.external_data: a data, ephemeral or action block of a type
//     that runs a local program when it is read, opened or invoked. Which
//     types do is rule-pack data (rules/defaults.yaml, program_data_sources,
//     program_ephemeral_resources and program_actions), not code here.
//   - ctf.exec.module_endpoint: a module called from inside another module,
//     installed from a source the endpoint allowlist does not admit, read the
//     way ctf.coverage.module_source reads it. A call the root makes is
//     module_source's subject at scan time, so the two never report the same
//     source.
//   - ctf.exec.module_uninspected: a module call whose files were not
//     inspected. At pre_plan, a "../" local module directory that does not
//     exist yet (scan runs before init), and, in an archive built without
//     LocalCalls that is not Partial (a file list is), a "./" or "../" call
//     that names no directory the archive carries. At post_init, a module block modules.json holds no
//     record for. Every subject but the absent "../" one carries
//     ctfkit.UnresolvedModule, so no waiver covers it. A directory a record
//     names that cannot be read fails the run instead (exit 2).
//
// A "./" or "../" local module is read wherever it lies, inside the root or
// beside it: its source is explicit and terraform runs what it names.
//
// provisioner and external_data run at two stages. At pre_plan (scan) they
// read every file scan read plus the local modules it calls that its walk did
// not read, so a configuration with no compliance.tf module gets them too. At
// post_init (report) they read the files directly in the root and in every
// directory .terraform/modules/modules.json lists, so a module a downloaded
// module calls is read too. module_endpoint runs at post_init only.
//
// Every file counts: override files, which can add a provisioner to a
// resource, and a .tf file whose .tofu twin shadows it under OpenTofu but
// which Terraform reads. Reading more than either binary does can only report
// more.
package codeexec

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/compliancetf/ctfkit/internal/analyzer/modulesource"
	"github.com/compliancetf/ctfkit/internal/parser"
	"github.com/compliancetf/ctfkit/internal/render/sarif"
	"github.com/compliancetf/ctfkit/internal/rulepack"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// The rule ids of the family. They are the SARIF ruleId, the exception join
// key and the taxonomy entry, so they never change once published.
const (
	ruleProvisioner       = "ctf.exec.provisioner"
	ruleExternalData      = "ctf.exec.external_data"
	ruleModuleEndpoint    = "ctf.exec.module_endpoint"
	ruleModuleUninspected = "ctf.exec.module_uninspected"
)

// Descriptors returns the tool.driver.rules entries of the family, for the
// runner to hand to the SARIF renderer.
func Descriptors() []sarif.RuleDescriptor {
	return sarif.WithHelpURI(sarif.AnalyzerDocs+"#code-that-runs-on-the-machine-that-plans-or-applies", []sarif.RuleDescriptor{
		{
			ID:               ruleProvisioner,
			ShortDescription: "The configuration or a module it installs declares a provisioner",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleExternalData,
			ShortDescription: "The configuration or a module it installs declares a data source, ephemeral resource or action that runs a local program",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleModuleEndpoint,
			ShortDescription: "A module called from inside another module is installed from a source outside the allowed module endpoints",
			Level:            ctfkit.LevelError,
		},
		{
			ID:               ruleModuleUninspected,
			ShortDescription: "A module call leads to no directory that was read, so its files were not inspected",
			Level:            ctfkit.LevelWarning,
		},
	})
}

// schemaVersion is the findings format version every finding of this family
// carries in ctf.schema.
const schemaVersion = "1.0"

// Message templates. They are analyzer constants formatted with addresses,
// provisioner and data source types, and a module source with its userinfo
// and query removed, never with an attribute value: a command, a program or a
// script is not quoted.
const (
	msgProvisioner      = "Provisioner %s in %s runs when this configuration is applied, with the access of the machine that applies it"
	msgExternalData     = "Data source %s runs a local program when this configuration is planned, with the access of the machine that plans it"
	msgProgramEphemeral = "Ephemeral resource %s runs a local program when this configuration is planned or applied, " +
		"with the access of the machine that runs it"
	msgProgramAction  = "Action %s runs a local program when this configuration is applied, with the access of the machine that applies it"
	msgModuleEndpoint = "Module %s is installed from %s, which is not an allowed module endpoint; " +
		"its code runs when this configuration is planned and applied"
	msgModuleUninspected = "Module %s names a local directory that does not exist, " +
		"so its files were not inspected for code that runs before plan"
	msgModuleUnfollowed = "Module %s names a local directory this run did not read, " +
		"so its files were not inspected for code that runs before plan"
	msgModuleUnrecorded = "Module %s has no record in " + modulesJSONPath + ", " +
		"so its files were not inspected for code that runs before plan"
)

// modulesJSONPath anchors a module finding whose module block is in no file
// this run read, so every finding still names a file.
const modulesJSONPath = ".terraform/modules/modules.json"

// Register adds the family to r: provisioner, external_data and
// module_uninspected at pre_plan and post_init, module_endpoint at post_init.
func Register(r ctfkit.Registry) {
	ctfkit.MustRegister(r,
		ProvisionerPrePlan{}, ExternalDataPrePlan{}, ModuleUninspectedPrePlan{},
		Provisioner{}, ExternalData{}, ModuleEndpoint{}, ModuleUninspected{},
	)
}

// ProvisionerPrePlan is ctf.exec.provisioner over the files scan read.
type ProvisionerPrePlan struct{}

// ID returns the rule id.
func (ProvisionerPrePlan) ID() string { return ruleProvisioner }

// Stage returns pre_plan.
func (ProvisionerPrePlan) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports one finding per provisioner block.
func (ProvisionerPrePlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return provisioners(ctx, in, ctfkit.PrePlan)
}

// Provisioner is ctf.exec.provisioner over the root and every installed
// module.
type Provisioner struct{}

// ID returns the rule id.
func (Provisioner) ID() string { return ruleProvisioner }

// Stage returns post_init, the first stage at which downloaded modules exist.
func (Provisioner) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per provisioner block.
func (Provisioner) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return provisioners(ctx, in, ctfkit.PostInit)
}

// ExternalDataPrePlan is ctf.exec.external_data over the files scan read.
type ExternalDataPrePlan struct{}

// ID returns the rule id.
func (ExternalDataPrePlan) ID() string { return ruleExternalData }

// Stage returns pre_plan.
func (ExternalDataPrePlan) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports one finding per data block of a program-running type.
func (ExternalDataPrePlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return externalData(ctx, in, ctfkit.PrePlan)
}

// ExternalData is ctf.exec.external_data over the root and every installed
// module.
type ExternalData struct{}

// ID returns the rule id.
func (ExternalData) ID() string { return ruleExternalData }

// Stage returns post_init.
func (ExternalData) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per data block of a program-running type.
func (ExternalData) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	return externalData(ctx, in, ctfkit.PostInit)
}

// provisioners is the one implementation of ctf.exec.provisioner.
func provisioners(ctx context.Context, in ctfkit.AnalyzerInput, stage ctfkit.Stage) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("codeexec: %w", err)
	}
	var out ctfkit.Findings
	for _, s := range scopes(in, stage) {
		for _, file := range s.files {
			parsed, err := parse(file, stage)
			if err != nil {
				return nil, err
			}
			for _, p := range parsed.Provisioners {
				address := s.prefix + p.Owner
				f, err := newFinding(ruleProvisioner, ctfkit.LevelError, stage,
					fmt.Sprintf(msgProvisioner, p.Type, address),
					s.uri(file.Path), p.Location.Region(), address, ctfkit.LogicalLocationResource)
				if err != nil {
					return nil, err
				}
				// Two provisioners of one resource share file, subject and
				// rule; their type tells them apart.
				f.Discriminator = p.Type
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// externalData is the one implementation of ctf.exec.external_data.
func externalData(ctx context.Context, in ctfkit.AnalyzerInput, stage ctfkit.Stage) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("codeexec: %w", err)
	}
	pack := rulepack.Embedded()
	kinds := []struct {
		types   []string
		blocks  func(*parser.ParseResult) []parser.DataSource
		mode    string
		message string
	}{
		{pack.ProgramDataSources(), func(p *parser.ParseResult) []parser.DataSource { return p.DataSources }, "data.", msgExternalData},
		{pack.ProgramEphemeralResources(), func(p *parser.ParseResult) []parser.DataSource { return p.EphemeralResources }, "ephemeral.", msgProgramEphemeral},
		{pack.ProgramActions(), func(p *parser.ParseResult) []parser.DataSource { return p.Actions }, "action.", msgProgramAction},
	}
	var out ctfkit.Findings
	for _, s := range scopes(in, stage) {
		for _, file := range s.files {
			parsed, err := parse(file, stage)
			if err != nil {
				return nil, err
			}
			for _, kind := range kinds {
				for _, d := range kind.blocks(parsed) {
					if !slices.Contains(kind.types, d.Type) {
						continue
					}
					address := s.prefix + scoped(d.Scope) + kind.mode + d.Type + "." + d.Name
					f, err := newFinding(ruleExternalData, ctfkit.LevelError, stage,
						fmt.Sprintf(kind.message, address),
						s.uri(file.Path), d.Location.Region(), address, ctfkit.LogicalLocationResource)
					if err != nil {
						return nil, err
					}
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}

// ModuleEndpoint is ctf.exec.module_endpoint.
type ModuleEndpoint struct{}

// ID returns the rule id.
func (ModuleEndpoint) ID() string { return ruleModuleEndpoint }

// Stage returns post_init.
func (ModuleEndpoint) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one finding per module called from inside another module
// whose source the endpoint allowlist does not admit. modules.json lists every
// module at every depth, so a module a downloaded module calls is checked
// however deep it sits.
func (ModuleEndpoint) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("codeexec: %w", err)
	}
	if in.Modules == nil {
		return nil, nil
	}
	sites, err := moduleSites(scopes(in, ctfkit.PostInit))
	if err != nil {
		return nil, err
	}
	var out ctfkit.Findings
	for _, instance := range in.Modules.Instances {
		// A call the root makes has no parent module; module_source judges it.
		if !strings.Contains(instance.Key, ".") || modulesource.EndpointAllowed(instance.Source, in.Settings.Endpoints) {
			continue
		}
		address := moduleAddress(instance.Key)
		at := siteOf(sites, instance)
		f, err := newFinding(ruleModuleEndpoint, ctfkit.LevelError, ctfkit.PostInit,
			fmt.Sprintf(msgModuleEndpoint, address, ctfkit.RedactSource(instance.Source)),
			at.file, at.region, address, ctfkit.LogicalLocationModule)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// ModuleUninspected is ctf.exec.module_uninspected over the module blocks of
// the root and of every installed module.
type ModuleUninspected struct{}

// ID returns the rule id.
func (ModuleUninspected) ID() string { return ruleModuleUninspected }

// Stage returns post_init.
func (ModuleUninspected) Stage() ctfkit.Stage { return ctfkit.PostInit }

// Analyze reports one warning per module block, in the root or in an
// installed module, that modules.json holds no record for: init
// records every call it installs, so the code of such a call, local or
// remote, was read by nothing here, and skipping it would leave the run
// looking clean. A local directory its source would join to is not read in
// its place: only a record says init installed it. The subject is the call's
// address followed by ctfkit.UnresolvedModule, so ctfkit.Decide never waives
// it. With no inventory there is no modules.json to hold a record, and the
// rule, like module_endpoint, reports nothing.
func (ModuleUninspected) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("codeexec: %w", err)
	}
	if in.Modules == nil {
		return nil, nil
	}
	recorded := make(map[string]bool, len(in.Modules.Instances))
	for _, instance := range in.Modules.Instances {
		recorded[moduleAddress(instance.Key)] = true
	}
	var out ctfkit.Findings
	for _, s := range scopes(in, ctfkit.PostInit) {
		for _, file := range s.files {
			parsed, err := parse(file, ctfkit.PostInit)
			if err != nil {
				return nil, err
			}
			for _, m := range parsed.Modules {
				address := s.prefix + "module." + m.Name
				if recorded[address] {
					continue
				}
				f, err := newFinding(ruleModuleUninspected, ctfkit.LevelWarning, ctfkit.PostInit,
					fmt.Sprintf(msgModuleUnrecorded, address), s.uri(file.Path), m.Location.Region(),
					address+"."+ctfkit.UnresolvedModule, ctfkit.LogicalLocationModule)
				if err != nil {
					return nil, err
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// ModuleUninspectedPrePlan is ctf.exec.module_uninspected over the "../"
// local module directories a directory scan found absent, and over the calls
// of an archive built without LocalCalls that lead to no directory read.
type ModuleUninspectedPrePlan struct{}

// ID returns the rule id.
func (ModuleUninspectedPrePlan) ID() string { return ruleModuleUninspected }

// Stage returns pre_plan.
func (ModuleUninspectedPrePlan) Stage() ctfkit.Stage { return ctfkit.PrePlan }

// Analyze reports one warning per call of an unread local module, at the
// module block that makes it, under the full address of that call.
//
// A call LocalCalls has no entry for, whose source joined to the caller's
// directory names no directory the archive carries, is reported too (round
// 5): an archive an SDK caller builds carries no call graph, so a "./"
// directory that is missing, unreadable, a symlink out of the root or simply
// not given looks the same, and none of them is a call that runs nothing.
// Its subject is the call's address followed by ctfkit.UnresolvedModule, so
// ctfkit.Decide never waives it. A directory scan resolves every call in
// LocalCalls, so it never takes this path: there an absent "./" directory
// inside the root is one init will refuse. A Partial archive, such as the
// file list a pre-commit hook passes, skips it too: the operator chose the
// files, and a module directory the list leaves out is outside that choice,
// not a call the run failed to follow.
func (ModuleUninspectedPrePlan) Analyze(ctx context.Context, in ctfkit.AnalyzerInput) (ctfkit.Findings, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("codeexec: %w", err)
	}
	if in.Config == nil {
		return nil, nil
	}
	unread := map[string]bool{}
	for _, module := range in.Config.LocalModules {
		if module.Unread {
			unread[module.Dir] = true
		}
	}
	byDir, dirs := filesByDir(in.Config)
	calls := localCalls(in.Config, byDir, dirs)
	if in.Config.Partial {
		calls.unfollowed = nil
	}
	if len(unread) == 0 && len(calls.unfollowed) == 0 {
		return nil, nil
	}
	var out ctfkit.Findings
	emit := func(s scope, file ctfkit.ConfigFile, m parser.Module, text, subject string) error {
		f, err := newFinding(ruleModuleUninspected, ctfkit.LevelWarning, ctfkit.PrePlan,
			fmt.Sprintf(text, s.prefix+"module."+m.Name),
			s.uri(file.Path), m.Location.Region(), subject, ctfkit.LogicalLocationModule)
		if err == nil {
			out = append(out, f)
		}
		return err
	}
	for _, s := range scopes(in, ctfkit.PrePlan) {
		for _, file := range s.files {
			parsed, _ := parse(file, ctfkit.PrePlan)
			for _, m := range parsed.Modules {
				address := s.prefix + "module." + m.Name
				if calls.unfollowed[[2]string{s.dir, m.Name}] {
					if err := emit(s, file, m, msgModuleUnfollowed, address+"."+ctfkit.UnresolvedModule); err != nil {
						return nil, err
					}
				}
				if slices.ContainsFunc(calls.to[s.dir][m.Name], func(to string) bool { return unread[to] }) {
					if err := emit(s, file, m, msgModuleUninspected, address); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return out, nil
}

// scope is the files of one module and the address prefix its blocks take.
type scope struct {
	// dir is the directory of the files at pre_plan, as their paths name it.
	dir string
	// prefix is "" for the root and, for example, "module.app.module.db."
	// for the instance keyed app.db.
	prefix string
	files  []ctfkit.ConfigFile
}

// uri is a file path as a finding's location carries it: through
// redactPath, for every file. A module directory, inside the root or beside
// it, is named after the source that calls it and may carry userinfo or a
// query; redacting every path is what keeps a called module's directory
// covered wherever the walk found it. A path with neither is unchanged.
func (scope) uri(file string) string {
	return redactPath(file)
}

// redactPath is ctfkit.RedactPath: "../CANARY-u:CANARY-t@shared/main.tf"
// becomes "../shared/main.tf" and a "dir?sshkey=..." component loses its
// query.
func redactPath(p string) string { return ctfkit.RedactPath(p) }

// scoped is the address segment of a data block's scope, "check.<name>." for
// one nested in a check block and empty at top level.
func scoped(scope string) string {
	if scope == "" {
		return ""
	}
	return scope + "."
}

// scopes are the files a stage reads.
//
// At pre_plan that is every file scan read, the root and any local module
// directory under it, then the files of each local module outside it, once per
// call path that reaches the directory (preplanScopes).
//
// At post_init it is the root module's own files, those directly in Root,
// followed by each installed instance's in modules.json order. A local module
// the configuration calls is an instance too, inside the root or outside it,
// so it is read once, from its own directory.
func scopes(in ctfkit.AnalyzerInput, stage ctfkit.Stage) []scope {
	if in.Config == nil && in.Modules == nil {
		return nil
	}
	if stage == ctfkit.PrePlan {
		if in.Config == nil {
			return nil
		}
		return preplanScopes(in.Config)
	}
	var out []scope
	if in.Config != nil {
		var root []ctfkit.ConfigFile
		for _, f := range in.Config.Files {
			if !strings.Contains(f.Path, "/") {
				root = append(root, f)
			}
		}
		out = append(out, scope{files: root})
	}
	if in.Modules != nil {
		for _, instance := range in.Modules.Instances {
			out = append(out, scope{prefix: moduleAddress(instance.Key) + ".", files: instance.Files})
		}
	}
	return out
}

// preplanScopes groups the files a scan read by directory and gives each
// directory the module addresses Terraform would give it: none for a
// configuration directory no local module call reaches (a root), and for a
// called one each caller's address plus module.<call name>, so module.a.module.b
// for a module b that module a calls. A directory reached by two call paths
// is one scope per path, so each of its blocks is reported once under every
// address it runs at; a call that names two directories, as a module block
// and its override can, leads to both. Roots are taken in path order and a
// directory's addresses sorted, so the output is the same on every run. A
// path stops at a directory already on it.
//
// A directory no root reaches is never given an empty prefix, which a
// waiver written for a root block would match: a local module directory no
// resolved call names, or one reached only through a cycle, takes
// module.<name>.<unresolved>. for each call that could not be followed (see
// localCalls), or module.<unresolved>. when there is none. ctfkit.Decide
// never waives such an address.
func preplanScopes(config *ctfkit.ConfigArchive) []scope {
	byDir, dirs := filesByDir(config)
	g := localCalls(config, byDir, dirs)

	called := map[string]bool{}
	for _, byName := range g.to {
		for _, targets := range byName {
			for _, to := range targets {
				called[to] = true
			}
		}
	}
	prefixes := map[string][]string{}
	var walk func(dir, prefix string, onPath map[string]bool)
	walk = func(dir, prefix string, onPath map[string]bool) {
		prefixes[dir] = append(prefixes[dir], prefix)
		onPath[dir] = true
		defer delete(onPath, dir)
		for _, name := range slices.Sorted(maps.Keys(g.to[dir])) {
			for _, to := range g.to[dir][name] {
				if _, read := byDir[to]; read && !onPath[to] {
					walk(to, prefix+"module."+name+".", onPath)
				}
			}
		}
	}
	configDirs := map[string]bool{}
	for _, f := range config.Files {
		configDirs[path.Dir(f.Path)] = true
	}
	sorted := slices.Sorted(slices.Values(dirs))
	for _, dir := range sorted {
		if configDirs[dir] && !called[dir] {
			walk(dir, "", map[string]bool{})
		}
	}

	markers := []string{"module." + ctfkit.UnresolvedModule + "."}
	if len(g.unresolved) > 0 {
		markers = markers[:0]
		for _, name := range g.unresolved {
			markers = append(markers, "module."+name+"."+ctfkit.UnresolvedModule+".")
		}
	}
	// Uncalled directories first, so a directory one of them calls takes
	// the caller's address; then whatever only a cycle reaches.
	for _, uncalledOnly := range []bool{true, false} {
		for _, dir := range sorted {
			if len(prefixes[dir]) > 0 || uncalledOnly && called[dir] {
				continue
			}
			for _, m := range markers {
				walk(dir, m, map[string]bool{})
			}
		}
	}

	out := make([]scope, 0, len(dirs))
	for _, dir := range dirs {
		ps := slices.Clone(prefixes[dir])
		slices.Sort(ps)
		for _, p := range slices.Compact(ps) {
			out = append(out, scope{dir: dir, prefix: p, files: byDir[dir]})
		}
	}
	return out
}

// filesByDir groups every file a scan read, the configuration's and the local
// modules', by directory, with the directories in the order first seen.
func filesByDir(config *ctfkit.ConfigArchive) (map[string][]ctfkit.ConfigFile, []string) {
	files := append([]ctfkit.ConfigFile(nil), config.Files...)
	for _, module := range config.LocalModules {
		files = append(files, module.Files...)
	}
	byDir := map[string][]ctfkit.ConfigFile{}
	var dirs []string
	for _, f := range files {
		dir := path.Dir(f.Path)
		if _, ok := byDir[dir]; !ok {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], f)
	}
	return byDir, dirs
}

// callGraph is the "./" and "../" module calls of a pre_plan scan.
type callGraph struct {
	// to maps a directory and a call name to the directories the call leads
	// to, sorted: more than one when a module block and its override name
	// different sources.
	to map[string]map[string][]string
	// unresolved are the names, sorted, of the calls LocalCalls holds no
	// entry for whose source, joined to the caller's directory, names no
	// directory the scan read or found absent.
	unresolved []string
	// unfollowed are those calls by caller directory and name.
	unfollowed map[[2]string]bool
}

// localCalls is the call graph of a scan. A directory scan carries its calls
// resolved, in LocalCalls, the way init resolves them, so a "../alias" that
// is a symlink to "../libs/pkg" leads to the directory the files were read
// from. A module block LocalCalls has no entry for, in an archive built
// without them or with only some, leads to its source joined to the
// caller's directory, and is unresolved when that names nothing the scan
// read. A call to the caller's own directory is dropped.
func localCalls(config *ctfkit.ConfigArchive, byDir map[string][]ctfkit.ConfigFile, dirs []string) callGraph {
	g := callGraph{to: map[string]map[string][]string{}, unfollowed: map[[2]string]bool{}}
	add := func(from, name, to string) {
		if to == from {
			return
		}
		if g.to[from] == nil {
			g.to[from] = map[string][]string{}
		}
		if !slices.Contains(g.to[from][name], to) {
			g.to[from][name] = append(g.to[from][name], to)
		}
	}
	known := map[[2]string]bool{}
	for _, c := range config.LocalCalls {
		known[[2]string{c.From, c.Name}] = true
		add(c.From, c.Name, c.To)
	}
	// listed are the local module directories the archive carries, read or
	// absent; a read one with no configuration file has no entry in byDir.
	listed := map[string]bool{}
	for _, module := range config.LocalModules {
		listed[module.Dir] = true
	}
	for _, dir := range dirs {
		for _, f := range byDir[dir] {
			parsed, _ := parse(f, ctfkit.PrePlan)
			for _, m := range parsed.Modules {
				// A ".\" or "..\" source is local on every platform and
				// init reads it with slashes; nothing is trimmed, as init
				// trims nothing.
				source := strings.ReplaceAll(m.Source, `\`, "/")
				if known[[2]string{dir, m.Name}] || !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
					continue
				}
				to := path.Join(dir, source)
				add(dir, m.Name, to)
				if _, read := byDir[to]; !read && !listed[to] {
					g.unresolved = append(g.unresolved, m.Name)
					g.unfollowed[[2]string{dir, m.Name}] = true
				}
			}
		}
	}
	for _, byName := range g.to {
		for _, targets := range byName {
			slices.Sort(targets)
		}
	}
	slices.Sort(g.unresolved)
	g.unresolved = slices.Compact(g.unresolved)
	return g
}

// site is where one module block is declared.
type site struct {
	file    string
	region  *ctfkit.Region
	source  string
	primary bool
}

// moduleSites indexes every module block by the prefix of the module it sits
// in and by its name.
func moduleSites(all []scope) (map[string]map[string][]site, error) {
	out := make(map[string]map[string][]site, len(all))
	for _, s := range all {
		primary := make(map[string]bool, len(s.files))
		for _, f := range parser.PrimaryFiles(s.files) {
			primary[f.Path] = true
		}
		byName := make(map[string][]site)
		for _, file := range s.files {
			parsed, err := parse(file, ctfkit.PostInit)
			if err != nil {
				return nil, err
			}
			for _, m := range parsed.Modules {
				byName[m.Name] = append(byName[m.Name], site{
					file: s.uri(file.Path), region: m.Location.Region(), source: m.Source, primary: primary[file.Path],
				})
			}
		}
		out[s.prefix] = byName
	}
	return out, nil
}

// siteOf is the module block that declares instance, in the files of the
// module that calls it.
func siteOf(sites map[string]map[string][]site, instance ctfkit.ModuleInstance) site {
	parent, name := "", instance.Key
	if i := strings.LastIndexByte(instance.Key, '.'); i >= 0 {
		parent, name = moduleAddress(instance.Key[:i])+".", instance.Key[i+1:]
	}
	return pick(sites[parent][name], instance.Source)
}

// pick chooses the block a finding points at: the one whose source is the
// source init installed, which is an override file's when one replaced it;
// else the first primary declaration; else any declaration; else
// modules.json, which names the instance even when no block was read.
func pick(candidates []site, source string) site {
	for _, c := range candidates {
		if c.source == source {
			return c
		}
	}
	for _, c := range candidates {
		if c.primary {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return site{file: modulesJSONPath}
}

// moduleAddress is the configuration address of a modules.json key, as
// ctf.coverage writes it: "app.db" is module.app.module.db. A module call
// name cannot contain a dot, so the split is exact.
func moduleAddress(key string) string {
	return "module." + strings.ReplaceAll(key, ".", ".module.")
}

// parse reads one file.
//
// At post_init a file that does not parse is an error, never an empty result:
// a block ctfkit cannot read is one it cannot say runs nothing, and terraform
// refuses such a file too. The error names the file and line only, since a
// parse diagnostic can quote the file's text.
//
// At pre_plan a file that does not parse contributes the blocks that did, the
// rule every other pre_plan analyzer follows: scan reads whole trees and file
// lists, a broken file is terraform's to report, and report checks the same
// files strictly after init.
func parse(file ctfkit.ConfigFile, stage ctfkit.Stage) (*parser.ParseResult, error) {
	parsed := parser.ParseConfigContent(file.Bytes, file.Path)
	if stage == ctfkit.PrePlan {
		return parsed, nil
	}
	for _, e := range parsed.Errors {
		if e.Severity == parser.ParseErrorError {
			// A ../ module's file is named after the source, so the path is
			// printed through RedactSource like any source.
			return nil, fmt.Errorf("codeexec: %s does not parse (line %d); "+
				"whether it runs code before plan cannot be told", redactPath(file.Path), e.Location.Line)
		}
	}
	return parsed, nil
}

// newFinding builds one finding of the family, with the file and lines of the
// block and its address. None of these rules names a control or a
// compliance.tf module that would have prevented it.
func newFinding(ruleID, level string, stage ctfkit.Stage, text, file string, region *ctfkit.Region,
	address, kind string,
) (ctfkit.Finding, error) {
	return ctfkit.NewFinding(ruleID, level, ctfkit.KindFail, ctfkit.Message{Text: text},
		[]ctfkit.Location{{
			PhysicalLocation: &ctfkit.PhysicalLocation{
				ArtifactLocation: ctfkit.ArtifactLocation{URI: file},
				Region:           region,
			},
			LogicalLocations: []ctfkit.LogicalLocation{{FullyQualifiedName: address, Kind: kind}},
		}},
		ctfkit.Properties{Schema: schemaVersion, Stage: stage})
}
