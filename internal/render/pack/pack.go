// Package pack builds the evidence pack of one `ctfkit report --out-dir` run:
// a document for readers who never run a CLI (QA and compliance staff,
// external auditors) that says which controls the installed compliance.tf
// modules enforce, which framework clauses each one maps to, what the catalog
// lists for the same resource types that these modules do not enforce, and
// which enforcement tests were supplied.
//
// Build turns what report already holds into a Pack value. Every rendered
// document (pack.json, pack.md, and later a PDF) is a function of that value
// alone, so the documents cannot disagree with each other. Write puts the
// rendered documents and the attachments (module manifests, receipt, SARIF,
// the pack schema) into one zip with fixed timestamps and sorted entries.
//
// The pack is unsigned. Nothing in it is attested or independently verified,
// and every rendering says so.
package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// Schema is the pack.json schema id.
const Schema = "ctf.evidence.pack/1"

// Notice is the line every rendering of the pack carries.
const Notice = "Unsigned. Not independently attested."

// manifestName is the file a served module carries its manifest in.
const manifestName = "compliancetf-manifest.json"

// Names of the attachments a pack zip holds besides the rendered documents.
const (
	FileReceipt = "receipt.json"
	FileSARIF   = "findings.sarif"
	FileSchema  = "pack-1.schema.json"
)

// Catalog sources a pack names on its cover.
const (
	SourceEmbedded = "embedded"
	SourceHome     = "home"
	SourceFile     = "file"
)

// Shows and DoesNotShow are the fixed template of section 3. They are the
// same in every pack; no caller supplies them.
var (
	Shows = []string{
		"Which compliance controls each installed compliance.tf module enforced when it was built, as the module manifest records them.",
		"The framework clauses each control is mapped to, with supporting clauses marked as partial or indirect evidence.",
		"Catalog controls for the same resource types that these modules do not enforce, and the layer that owns each one.",
		"The results of the enforcement tests supplied with this release, when tests were supplied.",
	}
	DoesNotShow = []string{
		"The state of resources running in AWS. Check that with AWS Config or Audit Manager.",
		"Organizational or process controls.",
		"Operation after deployment.",
		"Computer system validation: no CSV, IQ, OQ or PQ activities, e-signature logic or audit-trail business logic.",
	}
)

// Pack is the evidence pack of one blueprint release: everything every
// rendering reads. Field order is the order of the sections.
type Pack struct {
	Schema      string    `json:"schema"`
	Notice      string    `json:"notice"`
	Release     Release   `json:"release"`
	Generator   Generator `json:"generator"`
	GeneratedAt string    `json:"generatedAt"`
	Catalog     Catalog   `json:"catalog"`
	// Frameworks are the frameworks the installed modules enforce controls
	// for, sorted by id.
	Frameworks  []Framework         `json:"frameworks"`
	Summary     Summary             `json:"summary"`
	Scope       []Module            `json:"scope"`
	Shows       []string            `json:"shows"`
	DoesNotShow []string            `json:"doesNotShow"`
	Mapping     []ModuleMapping     `json:"mapping"`
	NoClause    []NoClauseControl   `json:"noClause"`
	NotEnforced []NotEnforced       `json:"notEnforced"`
	Tests       Tests               `json:"tests"`
	Register    []RegisterFramework `json:"register"`
	// Files are the attachments of the zip with their digests: the module
	// manifests, the receipt, the SARIF and the pack schema. The rendered
	// documents are not listed, since they are rendered from this value.
	Files []FileRef `json:"files"`
}

// Release identifies what the pack reports on.
type Release struct {
	// Name is the repository the run detected, else the root report read.
	Name     string `json:"name"`
	Root     string `json:"root"`
	Commit   string `json:"commit"`
	Platform string `json:"platform"`
	RunID    string `json:"runId"`
}

// Generator names the program that built the pack.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Catalog is the control catalog the coverage view read.
type Catalog struct {
	Version string `json:"version"`
	// Source is embedded, home (the file catalog pull writes) or file (named
	// with --catalog).
	Source string `json:"source"`
	// EmbeddedSubset is true when the catalog is the embedded release, which
	// holds the CIS v6.0 controls only.
	EmbeddedSubset bool `json:"embeddedSubset"`
}

// Framework is one framework id and its display name.
type Framework struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Summary holds the counts of section 1.
type Summary struct {
	Modules             int              `json:"modules"`
	ModulesWithManifest int              `json:"modulesWithManifest"`
	ControlsEnforced    int              `json:"controlsEnforced"`
	ControlsDelegated   int              `json:"controlsDelegated"`
	PerFramework        []FrameworkCount `json:"perFramework"`
	// NoClause counts control and framework pairs with no clause;
	// NoClauseWithReason those of them the catalog gives a reason for.
	NoClause           int `json:"noClause"`
	NoClauseWithReason int `json:"noClauseWithReason"`
	NotEnforced        int `json:"notEnforced"`
	// FindingsAtError counts unsuppressed error-level findings of the run.
	FindingsAtError int `json:"findingsAtError"`
}

// FrameworkCount is how many of the controls of the modules that enforce for
// a framework have at least one clause in it.
type FrameworkCount struct {
	Framework  string `json:"framework"`
	WithClause int    `json:"withClause"`
	Of         int    `json:"of"`
}

// Module is one installed module instance (section 2).
type Module struct {
	Key     string `json:"key"`
	Source  string `json:"source"`
	Version string `json:"version"`
	// ManifestSHA256 and ManifestFile are empty when the instance has no
	// manifest.
	ManifestSHA256      string `json:"manifestSha256"`
	ManifestFile        string `json:"manifestFile"`
	DeclaresNoResources bool   `json:"declaresNoResources"`
}

// ModuleMapping is the control-to-clause mapping of one module (section 4).
type ModuleMapping struct {
	Module     string          `json:"module"`
	Frameworks []string        `json:"frameworks"`
	Controls   []MappedControl `json:"controls"`
}

// MappedControl is one control of a manifest with its clauses per framework.
type MappedControl struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// Clauses holds one entry per framework of the module, in its order; an
	// entry with no clauses is a gap that section 5 explains.
	Clauses []FrameworkClauses `json:"clauses"`
}

// FrameworkClauses are the clauses of one control in one framework.
type FrameworkClauses struct {
	Framework string      `json:"framework"`
	Clauses   []ClauseRef `json:"clauses"`
}

// ClauseRef is one clause identifier. Supporting marks a clause the manifest
// classifies as partial or indirect evidence.
type ClauseRef struct {
	ID         string `json:"id"`
	Supporting bool   `json:"supporting"`
}

// NoClauseControl is a control with no applicable clause in one or more
// frameworks (section 5).
type NoClauseControl struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Frameworks []NoClauses `json:"frameworks"`
}

// NoClauses is one framework a control has no clause in. Reason is empty when
// the catalog records none.
type NoClauses struct {
	Framework string `json:"framework"`
	Reason    string `json:"reason"`
}

// NotEnforced is a catalog control for a resource type of these modules that
// no module manifest lists (section 6). Layer and Reason are empty when the
// catalog records no enforcement; SupersededBy names the stricter control a
// manifest records in its place.
type NotEnforced struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ResourceTypes []string `json:"resourceTypes"`
	Layer         string   `json:"layer"`
	Reason        string   `json:"reason"`
	SupersededBy  string   `json:"supersededBy"`
}

// Tests are the imported enforcement test results (section 7).
type Tests struct {
	Supplied bool       `json:"supplied"`
	File     string     `json:"file"`
	SHA256   string     `json:"sha256"`
	Runs     int        `json:"runs"`
	Passed   int        `json:"passed"`
	Failed   int        `json:"failed"`
	Errored  int        `json:"errored"`
	Skipped  int        `json:"skipped"`
	Cases    []TestCase `json:"cases"`
}

// TestCase is one run block of the test document.
type TestCase struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	ModuleKey string `json:"moduleKey"`
}

// RegisterFramework is the clause register of one framework (annex A).
type RegisterFramework struct {
	Framework     string                `json:"framework"`
	Name          string                `json:"name"`
	Clauses       []RegisterClause      `json:"clauses"`
	NotApplicable []NotApplicableClause `json:"notApplicable"`
}

// RegisterClause is one cited clause, its title as the manifest names it and
// the controls citing it.
type RegisterClause struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Controls []string `json:"controls"`
}

// NotApplicableClause is a clause the catalog records no control applies to.
type NotApplicableClause struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// FileRef is one attachment of the zip and the SHA-256 of its bytes.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Input is what report hands the builder.
type Input struct {
	Modules        *ctfkit.ModuleInventory
	Catalog        ctfkit.ControlCatalog
	CatalogVersion ctfkit.CatalogVersion
	// NotApplicableClauses is the catalog's framework id to clause to reason
	// map, nil when it records none.
	NotApplicableClauses map[string]map[string]string
	Findings             ctfkit.Findings
	Tests                *ctfkit.TestRun
	Metadata             ctfkit.RunMetadata
	Root                 string
	Generator            Generator
	// Receipt and SARIF are the rendered projections of the same run.
	Receipt []byte
	SARIF   []byte
}

// Build assembles the pack and its attachments. It reads each manifest again
// from disk and refuses one whose bytes no longer match the digest the loader
// recorded, so the copy in the zip is the document the run analyzed.
func Build(in Input) (*Pack, []File, error) {
	p := &Pack{
		Schema:      Schema,
		Notice:      Notice,
		Release:     release(in),
		Generator:   in.Generator,
		GeneratedAt: in.Metadata.Now.UTC().Format(time.RFC3339),
		Catalog:     catalogFacts(in.CatalogVersion),
		Shows:       Shows,
		DoesNotShow: DoesNotShow,
		Tests:       tests(in.Tests),
	}

	attachments, err := p.addScope(in)
	if err != nil {
		return nil, nil, err
	}
	attachments = append(attachments,
		File{Name: FileReceipt, Body: in.Receipt},
		File{Name: FileSARIF, Body: in.SARIF},
		File{Name: FileSchema, Body: schemaJSON},
	)
	sort.Slice(attachments, func(i, j int) bool { return attachments[i].Name < attachments[j].Name })
	for _, f := range attachments {
		p.Files = append(p.Files, FileRef{Path: f.Name, SHA256: digest(f.Body)})
	}

	p.addMapping(in.Modules)
	p.addNoClause(in.Catalog)
	p.addNotEnforced(in.Modules, in.Catalog)
	p.addRegister(in.Modules, in.NotApplicableClauses)
	p.addSummary(in.Findings)

	return p, attachments, nil
}

func release(in Input) Release {
	r := Release{
		Name:     in.Metadata.Workspace,
		Root:     in.Root,
		Commit:   in.Metadata.Commit,
		Platform: in.Metadata.Platform,
		RunID:    in.Metadata.RunID,
	}
	if r.Name == "" {
		r.Name = in.Root
	}
	return r
}

func catalogFacts(v ctfkit.CatalogVersion) Catalog {
	return Catalog{
		Version: v.Version,
		Source:  v.Provenance,
		// The version test, not the provenance, so a file copy of the
		// embedded catalog is named for what it holds.
		EmbeddedSubset: catalog.EmbeddedSubsetNote(v) != "",
	}
}

func tests(run *ctfkit.TestRun) Tests {
	if run == nil {
		return Tests{Cases: []TestCase{}}
	}
	t := Tests{
		Supplied: true,
		File:     run.File,
		SHA256:   run.SHA256,
		Runs:     run.Runs,
		Passed:   run.Passed,
		Failed:   run.Failed,
		Errored:  run.Errored,
		Skipped:  run.Skipped,
		Cases:    make([]TestCase, 0, len(run.Cases)),
	}
	for _, c := range run.Cases {
		t.Cases = append(t.Cases, TestCase{Name: c.Name, Status: c.Status, ModuleKey: c.ModuleKey})
	}
	return t
}

// instances are the module instances of the configuration, the root entry
// left out.
func instances(inv *ctfkit.ModuleInventory) []ctfkit.ModuleInstance {
	var out []ctfkit.ModuleInstance
	for _, inst := range inv.Instances {
		if inst.Key != "" {
			out = append(out, inst)
		}
	}
	return out
}

func (p *Pack) addScope(in Input) ([]File, error) {
	var files []File
	p.Scope = []Module{}
	seenFW := map[string]bool{}
	for _, inst := range instances(in.Modules) {
		m := Module{Key: inst.Key, Source: inst.Source, DeclaresNoResources: inst.DeclaresNoResources}
		if inst.Manifest != nil {
			body, err := readManifest(in.Root, inst)
			if err != nil {
				return nil, err
			}
			m.Version = inst.Manifest.Module.Version
			m.ManifestSHA256 = inst.ManifestSHA256
			m.ManifestFile = "manifests/" + inst.Key + "/" + manifestName
			if err := checkEntryName(m.ManifestFile); err != nil {
				return nil, err
			}
			files = append(files, File{Name: m.ManifestFile, Body: body})

			for _, fw := range inst.Manifest.Module.Frameworks {
				if seenFW[fw] {
					continue
				}
				seenFW[fw] = true
				name := inst.Manifest.Module.FrameworkNames[fw]
				if name == "" {
					name = fw
				}
				p.Frameworks = append(p.Frameworks, Framework{ID: fw, Name: name})
			}
		}
		p.Scope = append(p.Scope, m)
	}
	sort.Slice(p.Frameworks, func(i, j int) bool { return p.Frameworks[i].ID < p.Frameworks[j].ID })
	if p.Frameworks == nil {
		p.Frameworks = []Framework{}
	}
	return files, nil
}

func readManifest(root string, inst ctfkit.ModuleInstance) ([]byte, error) {
	path := filepath.Join(root, filepath.FromSlash(inst.Dir), manifestName)
	body, err := os.ReadFile(path) // #nosec G304 -- the manifest the loader already read under the report root
	if err != nil {
		return nil, fmt.Errorf("evidence pack: reading %s: %w", path, err)
	}
	if digest(body) != inst.ManifestSHA256 {
		return nil, fmt.Errorf("evidence pack: %s changed while the report ran", path)
	}
	return body, nil
}

func (p *Pack) addMapping(inv *ctfkit.ModuleInventory) {
	p.Mapping = []ModuleMapping{}
	for _, inst := range instances(inv) {
		if inst.Manifest == nil {
			continue
		}
		mm := ModuleMapping{
			Module:     inst.Key,
			Frameworks: append([]string{}, inst.Manifest.Module.Frameworks...),
			Controls:   []MappedControl{},
		}
		for _, c := range inst.Manifest.Controls {
			mc := MappedControl{ID: c.ControlID, Name: c.Name, Status: c.Status, Clauses: []FrameworkClauses{}}
			for _, fw := range mm.Frameworks {
				supporting := map[string]bool{}
				for _, id := range catalog.ClauseIdentifiers(c.SupportingClausesByFramework[fw]) {
					supporting[id] = true
				}
				fc := FrameworkClauses{Framework: fw, Clauses: []ClauseRef{}}
				for _, id := range catalog.ClauseIdentifiers(c.ClausesByFramework[fw]) {
					fc.Clauses = append(fc.Clauses, ClauseRef{ID: id, Supporting: supporting[id]})
				}
				mc.Clauses = append(mc.Clauses, fc)
			}
			mm.Controls = append(mm.Controls, mc)
		}
		p.Mapping = append(p.Mapping, mm)
	}
}

// addNoClause groups, per control, the frameworks of its module it maps to no
// clause in, with the catalog's reason. A control in several modules is
// listed once.
func (p *Pack) addNoClause(cat ctfkit.ControlCatalog) {
	p.NoClause = []NoClauseControl{}
	index := map[string]int{}
	seen := map[string]bool{}
	for _, mm := range p.Mapping {
		for _, mc := range mm.Controls {
			for _, fc := range mc.Clauses {
				if len(fc.Clauses) > 0 || seen[mc.ID+"\x00"+fc.Framework] {
					continue
				}
				seen[mc.ID+"\x00"+fc.Framework] = true
				i, ok := index[mc.ID]
				if !ok {
					i = len(p.NoClause)
					index[mc.ID] = i
					p.NoClause = append(p.NoClause, NoClauseControl{ID: mc.ID, Name: mc.Name})
				}
				reason := ""
				if ref, found := cat.Control(ctfkit.ControlID(mc.ID)); found {
					reason = ref.NotApplicable[fc.Framework]
				}
				p.NoClause[i].Frameworks = append(p.NoClause[i].Frameworks, NoClauses{Framework: fc.Framework, Reason: reason})
			}
		}
	}
	sort.Slice(p.NoClause, func(i, j int) bool { return p.NoClause[i].ID < p.NoClause[j].ID })
}

// addNotEnforced lists the catalog controls for the resource types these
// modules cover that no manifest lists. The resource types are those the
// catalog gives for the controls the manifests list, plus those of the catalog
// module entry whose source path matches an installed module's.
func (p *Pack) addNotEnforced(inv *ctfkit.ModuleInventory, cat ctfkit.ControlCatalog) {
	p.NotEnforced = []NotEnforced{}
	listed := map[string]bool{}
	superseded := map[string]string{}
	types := map[string]bool{}
	var sources []string
	for _, inst := range instances(inv) {
		if inst.Manifest == nil {
			continue
		}
		sources = append(sources, inst.Source)
		for _, c := range inst.Manifest.Controls {
			listed[c.ControlID] = true
			if ref, ok := cat.Control(ctfkit.ControlID(c.ControlID)); ok {
				for _, rt := range ref.ResourceTypes {
					types[rt] = true
				}
			}
		}
		for weak, strong := range inst.Manifest.Build.ControlsSuperseded {
			superseded[weak] = strong
		}
	}
	for _, m := range cat.Modules() {
		if installedFrom(m.Source, sources) {
			for _, rt := range m.ResourceTypes {
				types[rt] = true
			}
		}
	}

	added := map[ctfkit.ControlID]bool{}
	for _, rt := range sortedKeys(types) {
		for _, id := range cat.ControlsFor(rt) {
			if listed[string(id)] || added[id] {
				continue
			}
			added[id] = true
			ref, _ := cat.Control(id)
			ne := NotEnforced{
				ID:            string(id),
				Name:          ref.Name,
				ResourceTypes: append([]string{}, ref.ResourceTypes...),
				SupersededBy:  superseded[string(id)],
			}
			if ref.Enforcement != nil {
				ne.Layer, ne.Reason = ref.Enforcement.Layer, ref.Enforcement.Reason
			}
			p.NotEnforced = append(p.NotEnforced, ne)
		}
	}
	sort.Slice(p.NotEnforced, func(i, j int) bool { return p.NotEnforced[i].ID < p.NotEnforced[j].ID })
}

// hostPlaceholder is what a catalog module source carries in place of the
// registry host label.
const (
	hostPlaceholder = "{host}"
	registryDomain  = ".compliance.tf"
)

// installedFrom reports whether a catalog module source names one of the
// installed sources. Only a catalog source whose host is the template
// "{host}.compliance.tf" ignores the host, and then only against an installed
// host of the form <label>.compliance.tf; every other pair compares the whole
// source, so the same path on another registry does not match.
func installedFrom(catalogSource string, installed []string) bool {
	tmplHost, tmplPath, _ := strings.Cut(catalogSource, "/")
	templated := tmplHost == hostPlaceholder+registryDomain
	for _, src := range installed {
		if src == catalogSource {
			return true
		}
		if !templated {
			continue
		}
		host, path, ok := strings.Cut(src, "/")
		label, isRegistry := strings.CutSuffix(strings.ToLower(host), registryDomain)
		if ok && isRegistry && label != "" && !strings.Contains(label, ".") && path == tmplPath {
			return true
		}
	}
	return false
}

// addRegister lists, per framework, every clause the mapping cites with the
// controls citing it and its title as the manifests write it (the longest
// text seen for an identifier), then the clauses the catalog records no
// control applies to.
func (p *Pack) addRegister(inv *ctfkit.ModuleInventory, notApplicable map[string]map[string]string) {
	p.Register = []RegisterFramework{}
	for _, fw := range p.Frameworks {
		titles := map[string]string{}
		controls := map[string]map[string]bool{}
		for _, inst := range instances(inv) {
			if inst.Manifest == nil {
				continue
			}
			for _, c := range inst.Manifest.Controls {
				for _, title := range c.ClausesByFramework[fw.ID] {
					id := catalog.ClauseIdentifier(title)
					if id == "" {
						continue
					}
					if controls[id] == nil {
						controls[id] = map[string]bool{}
					}
					controls[id][c.ControlID] = true
					if t := clauseTitle(title, id); len(t) > len(titles[id]) {
						titles[id] = t
					}
				}
			}
		}
		rf := RegisterFramework{Framework: fw.ID, Name: fw.Name, Clauses: []RegisterClause{}, NotApplicable: []NotApplicableClause{}}
		for _, id := range naturalSorted(sortedKeys(controls)) {
			rf.Clauses = append(rf.Clauses, RegisterClause{ID: id, Title: titles[id], Controls: sortedKeys(controls[id])})
		}
		for _, id := range naturalSorted(sortedKeys(notApplicable[fw.ID])) {
			rf.NotApplicable = append(rf.NotApplicable, NotApplicableClause{ID: id, Reason: notApplicable[fw.ID][id]})
		}
		p.Register = append(p.Register, rf)
	}
}

func (p *Pack) addSummary(findings ctfkit.Findings) {
	s := Summary{PerFramework: []FrameworkCount{}}
	for _, m := range p.Scope {
		s.Modules++
		if m.ManifestFile != "" {
			s.ModulesWithManifest++
		}
	}
	enforced, delegated := map[string]bool{}, map[string]bool{}
	of, with := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, mm := range p.Mapping {
		for _, mc := range mm.Controls {
			switch mc.Status {
			case ctfkit.ManifestControlEnforced:
				enforced[mc.ID] = true
			case ctfkit.ManifestControlDelegated:
				delegated[mc.ID] = true
			}
			for _, fc := range mc.Clauses {
				if of[fc.Framework] == nil {
					of[fc.Framework], with[fc.Framework] = map[string]bool{}, map[string]bool{}
				}
				of[fc.Framework][mc.ID] = true
				if len(fc.Clauses) > 0 {
					with[fc.Framework][mc.ID] = true
				}
			}
		}
	}
	s.ControlsEnforced, s.ControlsDelegated = len(enforced), len(delegated)
	for _, fw := range p.Frameworks {
		s.PerFramework = append(s.PerFramework, FrameworkCount{Framework: fw.ID, WithClause: len(with[fw.ID]), Of: len(of[fw.ID])})
	}
	for _, nc := range p.NoClause {
		for _, f := range nc.Frameworks {
			s.NoClause++
			if f.Reason != "" {
				s.NoClauseWithReason++
			}
		}
	}
	s.NotEnforced = len(p.NotEnforced)
	for _, f := range findings {
		if !f.Suppressed() && f.Level == ctfkit.LevelError {
			s.FindingsAtError++
		}
	}
	p.Summary = s
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// clauseTitle is the text of a clause after its identifier: "CC7.2: The
// entity ..." becomes "The entity ...". A title that is its own identifier
// has no further text.
func clauseTitle(title, id string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(title), id)
	if !ok {
		return strings.TrimSpace(title)
	}
	return strings.TrimSpace(strings.TrimPrefix(rest, ":"))
}

// naturalSorted orders clause identifiers so that digit runs compare as
// numbers: CC2.1 before CC10.1, A1.2 before A1.10.
func naturalSorted(ids []string) []string {
	sort.SliceStable(ids, func(i, j int) bool { return naturalLess(ids[i], ids[j]) })
	return ids
}

func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		da, ra := leadingRun(a)
		db, rb := leadingRun(b)
		if da != db || ra != rb {
			if da && db {
				na, nb := strings.TrimLeft(ra, "0"), strings.TrimLeft(rb, "0")
				if len(na) != len(nb) {
					return len(na) < len(nb)
				}
				if na != nb {
					return na < nb
				}
			} else if ra != rb {
				return ra < rb
			}
		}
		a, b = a[len(ra):], b[len(rb):]
	}
	return len(a) < len(b)
}

// leadingRun returns the leading run of digits, or of non-digits, of s.
func leadingRun(s string) (bool, string) {
	digit := s[0] >= '0' && s[0] <= '9'
	i := 1
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') == digit {
		i++
	}
	return digit, s[:i]
}
