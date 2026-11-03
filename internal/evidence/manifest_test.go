package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const goldenChain = "c_1791201600000_0101010101010101"

// chainDir writes files (name to bytes) to a temp dir.
func chainDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestReadChains: the verified range, what is missing after it, and the
// break-glass flag per chain; refusals for what does not verify.
func TestReadChains(t *testing.T) {
	bl := breakLines(t)
	base, seg := join(bl[:2]), readFile(t, filepath.Join(goldens, "chain-segment.jsonl"))
	good := readFile(t, filepath.Join(goldens, "chain-good.jsonl"))
	cut := []byte(`{"chain":"c_1791201600000_0101`)
	bg := bytes.Replace(good, []byte(`"version":"2.0.0"}]`), []byte(`"version":"2.0.0","break_glass_id":"bobthecorp-override-1"}]`), 1)

	type want struct {
		lastSeq    int64
		terminated bool
		missing    []Range
		segments   int
	}
	for _, tc := range []struct {
		name  string
		files map[string][]byte
		want  want
	}{
		{"terminated", map[string][]byte{goldenChain + ".jsonl": good, "notes.txt": []byte("ignored")}, want{4, true, nil, 1}},
		{"stitched segments", map[string][]byte{goldenChain + ".jsonl": base, goldenChain + ".1.jsonl": seg}, want{4, true, nil, 2}},
		{"cut by a crash", map[string][]byte{goldenChain + ".jsonl": append(append([]byte{}, base...), cut...)}, want{1, false, []Range{{From: 2}}, 1}},
		{"hole in the segments", map[string][]byte{goldenChain + ".jsonl": base, goldenChain + ".2.jsonl": seg}, want{1, false, []Range{{From: 2}}, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chains, err := ReadChains(chainDir(t, tc.files))
			if err != nil {
				t.Fatal(err)
			}
			c := chains[0]
			if len(chains) != 1 || c.LastSeq != tc.want.lastSeq || c.Terminated != tc.want.terminated ||
				len(c.Segments) != tc.want.segments || len(c.Missing) != len(tc.want.missing) || c.BreakGlass {
				t.Fatalf("chain = %+v, want %+v", c, tc.want)
			}
			for i, r := range tc.want.missing {
				if c.Missing[i].From != r.From || c.Missing[i].To != nil {
					t.Errorf("missing[%d] = %+v, want %+v", i, c.Missing[i], r)
				}
			}
		})
	}

	t.Run("break-glass record", func(t *testing.T) {
		chains, err := ReadChains(chainDir(t, map[string][]byte{goldenChain + ".jsonl": rehash(t, bg)}))
		if err != nil {
			t.Fatal(err)
		}
		if !chains[0].BreakGlass {
			t.Error("a result with break_glass_id was not seen")
		}
	})

	for name, tc := range map[string]struct {
		files map[string][]byte
		want  error
	}{
		"no chains":            {map[string][]byte{"notes.txt": nil}, ErrEmpty},
		"no first segment":     {map[string][]byte{goldenChain + ".1.jsonl": seg}, ErrEmpty},
		"tampered":             {map[string][]byte{goldenChain + ".jsonl": readFile(t, filepath.Join(goldens, "chain-edited.jsonl"))}, ErrTampered},
		"file names another":   {map[string][]byte{"c_1791201600000_0202020202020202.jsonl": good}, ErrTampered},
		"segment after end":    {map[string][]byte{goldenChain + ".jsonl": good, goldenChain + ".2.jsonl": seg}, ErrTampered},
		"two runs":             {map[string][]byte{goldenChain + ".jsonl": good, "c_1791201600000_0202020202020202.jsonl": otherRun(t, good)}, ErrTampered},
		"not a segment name":   {map[string][]byte{"chain.jsonl": good}, nil},
		"only a cut first one": {map[string][]byte{goldenChain + ".jsonl": cut}, ErrEmpty},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadChains(chainDir(t, tc.files))
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("ReadChains = %v, want %v", err, tc.want)
			}
		})
	}
}

// rehash recomputes every prev of a chain whose lines were edited.
func rehash(t *testing.T, b []byte) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	for i := 1; i < len(lines); i++ {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(lines[i]))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		m["prev"] = hashLine(lines[i-1])
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(m); err != nil {
			t.Fatal(err)
		}
		lines[i] = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	return join(lines)
}

// otherRun is good as the chain 0202... of run bobthecorp-run-2.
func otherRun(t *testing.T, good []byte) []byte {
	t.Helper()
	b := bytes.ReplaceAll(good, []byte(goldenChain), []byte("c_1791201600000_0202020202020202"))
	return rehash(t, bytes.ReplaceAll(b, []byte("bobthecorp-run-1"), []byte("bobthecorp-run-2")))
}

// TestNewManifest: the manifest names every segment by key and digest, and
// every scalar is a string, as a signed document must be.
func TestNewManifest(t *testing.T) {
	good := readFile(t, filepath.Join(goldens, "chain-good.jsonl"))
	chains, err := ReadChains(chainDir(t, map[string][]byte{goldenChain + ".jsonl": good}))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManifest("bobthecorp", "default", "ci", "2026-10-19T12:00:00Z", "bobthecorp/default/bobthecorp-run-1/", chains)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Chains []struct {
			LastSeq  string `json:"last_seq"`
			Segments []SegmentRef
		} `json:"chains"`
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("a scalar is not a string: %v\n%s", err, raw)
	}
	if probe.RunID != "bobthecorp-run-1" || probe.Chains[0].LastSeq != "4" ||
		probe.Chains[0].Segments[0].Key != "bobthecorp/default/bobthecorp-run-1/"+goldenChain+".jsonl" {
		t.Errorf("manifest = %s", raw)
	}
}
