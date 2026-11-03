package fixturepin

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

// Hit is one match of the raw-bytes scanner. Excerpt is redacted: it is safe
// to print, which the matched bytes are not.
type Hit struct {
	Path       string
	Line       int
	Pattern    string
	Excerpt    string
	Credential bool // a literal token or a signed URL: the credential must be rotated
}

func (h Hit) String() string {
	return fmt.Sprintf("%s:%d: %s (%s)", h.Path, h.Line, h.Pattern, h.Excerpt)
}

type pattern struct {
	name       string
	re         *regexp.Regexp
	credential bool
}

// patterns are what no committed fixture may carry. A token shape or an
// absolute path is a pattern hit to investigate; a signed URL is a live
// credential in its own right.
var patterns = []pattern{
	{"signed URL", regexp.MustCompile(`(?i)[?&](x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|signature|sig)=`), true},
	{"URL with credentials", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s"'@]*:[^/\s"'@]+@`), false},
	{"TF_TOKEN variable", regexp.MustCompile(`TF_TOKEN_[A-Za-z0-9_]+`), false},
	{"credentials block", regexp.MustCompile(`credentials\s+"[^"]+"\s*\{`), false},
	{"registry token shape", regexp.MustCompile(`[A-Za-z0-9]{10,}\.atlasv1\.[A-Za-z0-9_-]{20,}`), false},
	{"GitHub token shape", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})`), false},
	{"GitLab token shape", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), false},
	{"Google API key shape", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), false},
	{"AWS access key shape", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), false},
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), false},
	{"JWT shape", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.`), false},
	{"authorization header", regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`), false},
	{"absolute path", regexp.MustCompile(`(^|[^A-Za-z0-9_.~/-])/(Users|home|private|tmp|var|root|opt|Volumes|etc|mnt|run)/`), false},
	{"file URL", regexp.MustCompile(`file://`), false},
	{"Windows path", regexp.MustCompile(`\b[A-Za-z]:\\`), false},
}

// Scan walks root and reports every pattern hit, plus every occurrence of a
// literal (the token the recorder was given). A symlink or any file that is
// not regular is refused outright: a fixture tree is plain files.
func Scan(root string, literals []string) ([]Hit, error) {
	var hits []Hit
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; a fixture tree holds plain files only", p)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		raw, readErr := os.ReadFile(p) //nolint:gosec // walking the tree under scan
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(root, p)
		hits = append(hits, scanBytes(filepath.ToSlash(rel), raw, literals)...)
		return nil
	})
	return hits, err
}

func scanBytes(name string, raw []byte, literals []string) []Hit {
	var hits []Hit
	// A token's charset allows + / =, so a URL may carry it percent-encoded;
	// both forms are the literal.
	var all []string
	for _, lit := range literals {
		all = append(all, lit)
		if enc := url.QueryEscape(lit); enc != lit {
			all = append(all, enc)
		}
	}
	for _, lit := range all {
		if lit == "" {
			continue
		}
		for off := 0; ; {
			i := bytes.Index(raw[off:], []byte(lit))
			if i < 0 {
				break
			}
			hits = append(hits, Hit{Path: name, Line: lineOf(raw, off+i), Pattern: "literal token", Excerpt: "redacted", Credential: true})
			off += i + len(lit)
		}
	}
	for _, p := range patterns {
		for _, loc := range p.re.FindAllIndex(raw, -1) {
			hits = append(hits, Hit{Path: name, Line: lineOf(raw, loc[0]), Pattern: p.name, Excerpt: redact(raw[loc[0]:loc[1]]), Credential: p.credential})
		}
	}
	return hits
}

// ScanExit is the recorder's exit code for a scan: 3 when a hit is a
// credential, 2 for any other hit, 0 for none.
func ScanExit(hits []Hit) int {
	code := 0
	for _, h := range hits {
		if h.Credential {
			return 3
		}
		code = 2
	}
	return code
}

func lineOf(raw []byte, off int) int { return bytes.Count(raw[:off], []byte("\n")) + 1 }

// redact keeps the first four bytes of a match, which name the shape without
// giving away the value.
func redact(m []byte) string {
	const keep = 4
	if len(m) <= keep {
		return "***"
	}
	return string(m[:keep]) + "***"
}
