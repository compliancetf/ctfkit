package ctfkit

import (
	"encoding/json"
	"sort"

	"github.com/compliancetf/ctfkit/pkg/verdict/jcs"
)

// SortFindings puts findings into the order every projection emits them in, so
// two runs over the same input produce the same bytes and a diff between two
// runs shows what changed rather than how the map iterated.
//
// The order is rule id, then the first physical location's uri, then its start
// line, then Subject. Where those are all equal the tie is broken by the
// canonical JSON of the finding itself, with the exception property left out
// so that suppressing a finding moves nothing.
func SortFindings(fs Findings) {
	keys := make([]string, len(fs))
	for i, f := range fs {
		keys[i] = f.tieBreaker()
	}

	idx := make([]int, len(fs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := fs[idx[a]], fs[idx[b]]
		if x.RuleID != y.RuleID {
			return x.RuleID < y.RuleID
		}
		ux, uy := firstURI(x), firstURI(y)
		if ux != uy {
			return ux < uy
		}
		lx, ly := firstLine(x), firstLine(y)
		if lx != ly {
			return lx < ly
		}
		sx, sy := x.Subject(), y.Subject()
		if sx != sy {
			return sx < sy
		}
		return keys[idx[a]] < keys[idx[b]]
	})

	sorted := make(Findings, len(fs))
	for i, j := range idx {
		sorted[i] = fs[j]
	}
	copy(fs, sorted)
}

// tieBreaker is the canonical JSON of the finding without its exception
// property. An unmarshalable finding sorts last under an empty key rather than
// failing a sort that has no way to report an error.
func (f Finding) tieBreaker() string {
	bare := f
	if f.Props.Exception != nil {
		bare.Props = f.Props
		bare.Props.Exception = nil
	}
	raw, err := json.Marshal(bare)
	if err != nil {
		return ""
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return ""
	}
	return string(canonical)
}

func firstURI(f Finding) string {
	for _, l := range f.Locations {
		if l.PhysicalLocation != nil {
			return l.PhysicalLocation.ArtifactLocation.URI
		}
	}
	return ""
}

func firstLine(f Finding) int {
	for _, l := range f.Locations {
		if l.PhysicalLocation != nil && l.PhysicalLocation.Region != nil {
			return l.PhysicalLocation.Region.StartLine
		}
	}
	return 0
}
