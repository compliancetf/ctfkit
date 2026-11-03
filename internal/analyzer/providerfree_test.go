// Package analyzer_test holds the check that keeps Terraform provider
// knowledge out of analyzer code: resource types, attribute names and tag
// attributes are rule pack data, under internal/rulepack/rules.
package analyzer_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/compliancetf/ctfkit/internal/rulepack"
)

// TestNoProviderResourceLiterals fails on any string literal in a non-test
// analyzer source file that holds a pack's resource prefix, such as "aws_".
// Comments and tests may name resource types; code may not.
func TestNoProviderResourceLiterals(t *testing.T) {
	prefixes := rulepack.Embedded().ResourcePrefixes()
	if len(prefixes) == 0 {
		t.Fatal("no pack declares a resource prefix, so this check proves nothing")
	}
	fset := token.NewFileSet()
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				value = lit.Value
			}
			for _, prefix := range prefixes {
				if strings.Contains(value, prefix) {
					t.Errorf("%s: string literal %s holds the resource prefix %q; move the provider fact into a rule pack",
						fset.Position(lit.Pos()), lit.Value, prefix)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no analyzer source file was checked")
	}
}
