// Package exceptions is the file backend of ctfkit.ExceptionRegistry: it turns
// a .ctf-exceptions.yaml document into an immutable snapshot the runner asks
// after an analyzer has returned.
//
// The file is a repository input. It can suppress a finding and every value it
// supplies is recorded in the run object, but it can never add or change a
// control id, a rule id or a remediation, so what it can do is bounded by what
// the catalog already said.
//
// Three loader rules carry the weight, and each one is a way the file could
// otherwise widen what is allowed without anybody noticing. A duplicate
// (control or rule, resource) pair is rejected, because two entries for one
// scope would make "the entry that applies" a property of file order rather
// than of intent. A missing file is an empty registry and not an error,
// because having no exceptions is the normal case. A malformed file fails the
// load, never an empty snapshot, so a typo can never quietly turn a file full
// of waivers into a file with none.
//
// Every error this package returns wraps ErrExceptions, which the command
// layer maps to exit 2 with the exceptions diagnostic prefix.
package exceptions

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/compliancetf/ctfkit/pkg/ctfkit"
)

// ErrExceptions marks every error this package returns. The command layer
// tests for it with errors.Is and reports exit 2 under the exceptions prefix.
var ErrExceptions = errors.New("exceptions error")

// FileName is the exceptions file Discover looks for in the configuration
// directory.
const FileName = ".ctf-exceptions.yaml"

// schemaMajor is the only exceptions-file major this build reads. A document
// declaring another one is an environment error, the same rule the catalog
// applies. The key is optional: the entry shape alone is a valid file.
const schemaMajor = "1"

// reviewDateLayout is the review date as the file writes it: a UTC date, no
// clock and no zone. The waiver runs through 23:59:59Z of that day.
const reviewDateLayout = "2006-01-02"

// FileExceptions is a loaded exceptions file: a preloaded, immutable snapshot
// that is safe for concurrent use, reads the system clock nowhere and fetches
// nothing. Every lookup answers from memory and hands back a copy, so a caller
// cannot reach back into it.
type FileExceptions struct {
	ctfkit.ExceptionRegistrySeal

	byControl map[scope]ctfkit.Exception
	byRule    map[scope]ctfkit.Exception
}

// scope is what one entry covers: an id and the resource address it is bound
// to. It is the key the loader refuses to see twice.
type scope struct {
	id       string
	resource string
}

// document is the file as written. Unknown keys are ignored rather than
// refused: the exceptions file schema carries governance fields this loader
// has no use for, such as the compensating controls and the risk assessment,
// and a file is not malformed for recording them.
type document struct {
	SchemaVersion string  `yaml:"schema_version"`
	Exceptions    []entry `yaml:"exceptions"`
}

// entry is one waiver.
//
// Two fields take either of two spellings, because the recorded fixtures and
// the SDK spec name them differently and both files are contract. The entry id
// is `id` when the file states one and the approval ticket otherwise, which is
// what the fixtures' expected output names. Approvers come from `approvals`,
// the list the spec names, and from `approved_by`, the single value the
// exceptions file schema and both fixtures carry.
type entry struct {
	Control        string   `yaml:"control"`
	Rule           string   `yaml:"rule"`
	ID             string   `yaml:"id"`
	ApprovalTicket string   `yaml:"approval_ticket"`
	Resource       string   `yaml:"resource"`
	Justification  string   `yaml:"justification"`
	Approvals      []string `yaml:"approvals"`
	ApprovedBy     string   `yaml:"approved_by"`
	ReviewDate     string   `yaml:"review_date"`
}

// Load reads an exceptions file. It returns an error wrapping ErrExceptions
// when the file cannot be read, does not parse, declares an unsupported schema
// major, or carries an entry that breaks one of the rules this package states.
func Load(path string) (*FileExceptions, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own --exceptions value or the discovery root's file name, and the file can only suppress findings, never add control ids
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrExceptions, path, err)
	}
	f, err := parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Discover reads the exceptions file of a configuration directory. A directory
// with no such file is an empty registry and not an error, because having no
// exceptions is the normal case; a file that exists and does not load is an
// error, because a waiver nobody can read is not a waiver nobody wrote.
func Discover(root string) (*FileExceptions, error) {
	path := filepath.Join(root, FileName)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return empty(), nil
		}
		return nil, fmt.Errorf("%w: reading %s: %w", ErrExceptions, path, err)
	}
	return Load(path)
}

// Match returns the control-level entry covering control on resource. The
// loader rejects a duplicate pair, so a scope holds at most one entry and it is
// both the first valid one and the first one of any kind.
func (f *FileExceptions) Match(control ctfkit.ControlID, resource string, _ time.Time) (ctfkit.Exception, bool) {
	e, ok := f.byControl[scope{id: string(control), resource: resource}]
	if !ok {
		return ctfkit.Exception{}, false
	}
	return copyOf(e), true
}

// MatchRule returns the rule-level entry covering ruleID on resource, by the
// same rule as Match. It is the only waiver that can reach a finding carrying
// no control id.
func (f *FileExceptions) MatchRule(ruleID, resource string, _ time.Time) (ctfkit.Exception, bool) {
	e, ok := f.byRule[scope{id: ruleID, resource: resource}]
	if !ok {
		return ctfkit.Exception{}, false
	}
	return copyOf(e), true
}

// IsValid reports whether e is in force at now: somebody approved it, and its
// review date has not passed. The review date is a UTC date and the waiver runs
// through the whole of that day, so an entry reviewed today is valid for every
// instant of today including the last fraction of a second. An entry with no
// review date is never valid: an open ended waiver is not evidence.
func (f *FileExceptions) IsValid(e ctfkit.Exception, now time.Time) bool {
	if len(e.Approvers) == 0 || e.ExpiresAt.IsZero() {
		return false
	}
	d := e.ExpiresAt.UTC()
	// The boundary is the exclusive next midnight rather than 23:59:59Z
	// itself: a run clock carries nanoseconds, and 23:59:59.5Z is still
	// inside the review day.
	nextMidnight := time.Date(d.Year(), d.Month(), d.Day()+1, 0, 0, 0, 0, time.UTC)
	return now.UTC().Before(nextMidnight)
}

// empty is the registry a directory with no exceptions file gets.
func empty() *FileExceptions {
	return &FileExceptions{
		byControl: map[scope]ctfkit.Exception{},
		byRule:    map[scope]ctfkit.Exception{},
	}
}

// parse turns exceptions bytes into a snapshot. The returned error always
// wraps ErrExceptions so a caller that skips Load still reports the right exit
// code.
func parse(b []byte) (*FileExceptions, error) {
	var doc document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: the exceptions file does not parse as YAML: %w", ErrExceptions, err)
	}
	if err := checkSchema(doc.SchemaVersion); err != nil {
		return nil, err
	}

	f := empty()
	for i, raw := range doc.Exceptions {
		e, err := convert(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: exception %d: %w", ErrExceptions, i+1, err)
		}

		// The table and the key both come from the entry convert built,
		// never from the raw fields again. Deciding twice from two sources
		// is how an entry ends up filed under a lookup nothing performs:
		// convert reads `rule: " "` as absent, and a second reading of the
		// raw field would read it as present.
		table, key := f.byControl, scope{id: string(e.ControlID), resource: e.Resource}
		if e.RuleID != "" {
			table, key = f.byRule, scope{id: e.RuleID, resource: e.Resource}
		}
		if _, dup := table[key]; dup {
			return nil, fmt.Errorf("%w: exception %d: %s and resource %s are waived twice, so which entry applies would depend on file order", ErrExceptions, i+1, key.id, key.resource)
		}
		table[key] = e
	}
	return f, nil
}

// convert validates one entry and returns it. Every field it reads is trimmed
// once here, so the entry it returns is the only version of itself the rest of
// the package sees.
func convert(raw entry) (ctfkit.Exception, error) {
	control, rule := strings.TrimSpace(raw.Control), strings.TrimSpace(raw.Rule)
	switch {
	case control != "" && rule != "":
		return ctfkit.Exception{}, errors.New("it names both a control and a rule, and an entry waives exactly one of them")
	case control == "" && rule == "":
		return ctfkit.Exception{}, errors.New("it names neither a control nor a rule, and an entry waives exactly one of them")
	}

	// A resource is trimmed here and nowhere else. A quoted value padded with
	// spaces would otherwise pass the emptiness check and then never equal
	// any resource address, which is an approved waiver lost in silence.
	resource := strings.TrimSpace(raw.Resource)
	if resource == "" {
		return ctfkit.Exception{}, errors.New("it names no resource, and a waiver with no resource would cover every one of them")
	}

	e := ctfkit.Exception{
		ID:            strings.TrimSpace(firstNonEmpty(raw.ID, raw.ApprovalTicket)),
		ControlID:     ctfkit.ControlID(control),
		RuleID:        rule,
		Resource:      resource,
		Justification: raw.Justification,
		Approvers:     approvers(raw),
	}

	if raw.ReviewDate != "" {
		d, err := time.ParseInLocation(reviewDateLayout, strings.TrimSpace(raw.ReviewDate), time.UTC)
		if err != nil {
			return ctfkit.Exception{}, fmt.Errorf("its review date %q is not a %s UTC date", raw.ReviewDate, reviewDateLayout)
		}
		e.ExpiresAt = d
	}

	return e, nil
}

// approvers collects both spellings the file may use, in the order it wrote
// them, so the recorded metadata is what the file says.
func approvers(raw entry) []string {
	out := make([]string, 0, len(raw.Approvals)+1)
	out = append(out, raw.Approvals...)
	if raw.ApprovedBy != "" {
		out = append(out, raw.ApprovedBy)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// checkSchema refuses a major this build does not read. The key is optional,
// because the entry shape alone is a valid file.
func checkSchema(version string) error {
	if version == "" {
		return nil
	}
	if major, _, _ := strings.Cut(version, "."); major != schemaMajor {
		return fmt.Errorf("%w: the exceptions file declares schema version %q, and this build reads major %s", ErrExceptions, version, schemaMajor)
	}
	return nil
}

// copyOf hands out a value a caller cannot use to reach back into the
// snapshot: the only reference field is the approver list, so it is copied.
func copyOf(e ctfkit.Exception) ctfkit.Exception {
	e.Approvers = append([]string(nil), e.Approvers...)
	return e
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
