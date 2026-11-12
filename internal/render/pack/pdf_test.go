package pack

import (
	"bytes"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pageObject matches a page object and not the page tree (/Type /Pages).
var pageObject = regexp.MustCompile(`/Type\s*/Page\b`)

// checkPDF is a minimal structural check with the standard library: the
// header, a startxref that points at the cross-reference table, the end
// marker, and the number of page objects.
func checkPDF(t *testing.T, body []byte) int {
	t.Helper()
	if !bytes.HasPrefix(body, []byte("%PDF-1.")) {
		t.Fatalf("no PDF header: %q", body[:min(len(body), 16)])
	}
	if !bytes.HasSuffix(bytes.TrimRight(body, "\r\n"), []byte("%%EOF")) {
		t.Fatal("no end-of-file marker at the end")
	}
	i := bytes.LastIndex(body, []byte("startxref"))
	if i < 0 {
		t.Fatal("no startxref")
	}
	off, err := strconv.Atoi(strings.Fields(string(body[i+len("startxref"):]))[0])
	if err != nil || off <= 0 || off >= len(body) || !bytes.HasPrefix(body[off:], []byte("xref")) {
		t.Fatalf("startxref %q does not point at the xref table", strings.Fields(string(body[i:]))[1])
	}
	return len(pageObject.FindAll(body, -1))
}

func TestRenderPDF(t *testing.T) {
	in, _ := fixture(t)
	p, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	first, err := RenderPDF(p)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderPDF(p)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != FilePDF {
		t.Errorf("name = %s, want %s", first.Name, FilePDF)
	}
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatal("two renderings of one pack differ")
	}
	pages := checkPDF(t, first.Body)
	if pages <= 1 {
		t.Fatalf("pages = %d, want more than 1", pages)
	}
	for _, want := range [][]byte{[]byte("/Producer"), []byte("/CreationDate(D:")} {
		if !bytes.Contains(first.Body, want) {
			t.Errorf("the PDF holds no %s", want)
		}
	}

	d, err := layoutPDF(p, pages, map[string]int{})
	if err != nil {
		t.Fatal(err)
	}
	if d.page != pages {
		t.Errorf("layout has %d pages, the PDF %d", d.page, pages)
	}
	drawn := squash(d.text)
	for _, s := range sectionTitles {
		if !strings.Contains(drawn, squash([]string{s.title})) {
			t.Errorf("the PDF does not draw the section title %q", s.title)
		}
	}
	if got := strings.Count(strings.Join(d.text, "\n"), Notice); got < pages+1 {
		t.Errorf("the notice is drawn %d times, want every footer and the cover", got)
	}
	if want := "Page 2 of " + strconv.Itoa(pages); !slices.Contains(d.text, want) {
		t.Errorf("no %q", want)
	}
}

// An empty pack still renders every section, and an empty one reads None.
func TestRenderPDFStatesWhatIsMissing(t *testing.T) {
	p := &Pack{Notice: Notice, Shows: Shows, DoesNotShow: DoesNotShow}
	f, err := RenderPDF(p)
	if err != nil {
		t.Fatal(err)
	}
	checkPDF(t, f.Body)
	d, err := layoutPDF(p, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(d.text, "\n")
	for _, want := range []string{"Not set", "No tests supplied."} {
		if !strings.Contains(squash(d.text), squash([]string{want})) {
			t.Errorf("an empty pack does not read %q", want)
		}
	}
	// Scope, mapping, sections 5 and 6 and the register.
	if got := strings.Count(text, none+"."); got < 5 {
		t.Errorf("an empty pack reads %q %d times, want 5", none+".", got)
	}
}

// squash joins drawn strings without spaces: wrapping draws a sentence one
// word at a time and drops the space at a line end.
func squash(text []string) string {
	return strings.ReplaceAll(strings.Join(text, ""), " ", "")
}

func TestSplitWords(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"two words", []string{"two ", "words"}},
		{"s3_bucket_logging", []string{"s3_", "bucket_", "logging"}},
		{"a  b", []string{"a  ", "b"}},
		{"x/y-z", []string{"x/", "y-", "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := splitWords(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitWords(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A word wider than its column is broken, and no line is wider than the
// column it was wrapped to.
func TestWrapBreaksALongWord(t *testing.T) {
	d, err := newPDFDoc("", 0)
	if err != nil {
		t.Fatal(err)
	}
	d.newPage()
	const w = 20.0
	lines := d.wrap([]run{mon(strings.Repeat("a", 64))}, sizeTable, w)
	if len(lines) < 2 {
		t.Fatalf("a 64-character sha256 fits in %d line in %v mm", len(lines), w)
	}
	var joined string
	for _, ln := range lines {
		for _, pc := range ln {
			if pc.x+pc.w > w+0.01 {
				t.Errorf("piece %q ends at %.2f mm, past %v", pc.text, pc.x+pc.w, w)
			}
			joined += pc.text
		}
	}
	if joined != strings.Repeat("a", 64) {
		t.Errorf("wrapping lost characters: %q", joined)
	}
}
