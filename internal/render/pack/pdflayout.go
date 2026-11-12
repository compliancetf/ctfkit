package pack

import (
	_ "embed"
	"fmt"
	"strings"
	"unicode/utf8"

	// gopdf: a maintained, pure-Go (no cgo) MIT PDF writer with TrueType
	// subsetting and UTF-8; the standard library writes no PDF.
	"github.com/signintech/gopdf"
)

// The fonts and the logo the PDF embeds; assets/README.md names their
// sources and licenses.
var (
	//go:embed assets/AtkinsonHyperlegibleNext-Regular.ttf
	fontSans []byte
	//go:embed assets/AtkinsonHyperlegibleNext-Bold.ttf
	fontBold []byte
	//go:embed assets/AtkinsonHyperlegibleMono-Regular.ttf
	fontMono []byte
	//go:embed assets/logo.png
	logoPNG []byte
)

// A4 in millimeters, and the text block inside the margins.
const (
	pageW     = 210.0
	pageH     = 297.0
	marginX   = 16.0
	bodyTop   = 20.0
	bodyEnd   = pageH - 20.0
	contentW  = pageW - 2*marginX
	ptToMM    = 25.4 / 72
	rule1     = 0.26 // 1px
	rule2     = 0.53 // 2px
	rule3     = 0.79 // 3px
	cellPadY  = 1.8
	cellPadX  = 3.0
	sizeBody  = 9.4
	sizeTable = 8.4
)

type rgb struct{ r, g, b uint8 }

// Brand colors.
var (
	violet = rgb{0x5c, 0x4f, 0xe5}
	ink    = rgb{0x15, 0x13, 0x2a}
	ink2   = rgb{0x4e, 0x4b, 0x63}
	mist   = rgb{0xf1, 0xef, 0xfe}
	grey   = rgb{0xd6, 0xd3, 0xe7}
)

// frameworkColors are the framework marks; any other framework uses ink.
var frameworkColors = map[string]rgb{
	"soc_2":           {0x1d, 0x4e, 0xd8},
	"eu_gmp_annex_11": {0x9f, 0x12, 0x39},
	"cfr_part_11":     {0x03, 0x69, 0xa1},
}

func frameworkColor(id string) rgb {
	if c, ok := frameworkColors[id]; ok {
		return c
	}
	return ink
}

type face string

const (
	sans face = "sans"
	bold face = "bold"
	mono face = "mono"
)

// run is a piece of text in one face and color. dashed underlines it, the
// mark of a supporting clause; mark puts a framework square before it.
type run struct {
	text   string
	face   face
	color  rgb
	dashed bool
	mark   *rgb
}

func txt(s string) run    { return run{text: s, face: sans, color: ink} }
func strong(s string) run { return run{text: s, face: bold, color: ink} }
func muted(s string) run  { return run{text: s, face: sans, color: ink2} }
func mon(s string) run    { return run{text: s, face: mono, color: ink} }

// fwRun is a framework name with its mark.
func fwRun(id, name string, f face) run {
	c := frameworkColor(id)
	return run{text: name, face: f, color: ink, mark: &c}
}

// inline turns Markdown-style text into runs: `code` spans become mono.
func inline(s string, base run) []run {
	var out []run
	for i, part := range strings.Split(s, "`") {
		if part == "" {
			continue
		}
		r := base
		r.text = part
		if i%2 == 1 {
			r.face = mono
		}
		out = append(out, r)
	}
	return out
}

// piece is a word of a run placed on a line.
type piece struct {
	run
	x, w float64
}

// pdfDoc is one pass of the layout. The first pass learns the page count and
// the page of every section; the second draws with them.
type pdfDoc struct {
	pdf      *gopdf.GoPdf
	y        float64
	page     int
	total    int
	header   string
	sections map[string]int
	// text is every string drawn, page by page, so tests can read the PDF
	// without a PDF parser.
	text []string
	err  error
	font face
	size float64
}

func newPDFDoc(header string, total int) (*pdfDoc, error) {
	pdf := &gopdf.GoPdf{}
	pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4, Unit: gopdf.UnitMM})
	for _, f := range []struct {
		name face
		data []byte
	}{{sans, fontSans}, {bold, fontBold}, {mono, fontMono}} {
		if err := pdf.AddTTFFontData(string(f.name), f.data); err != nil {
			return nil, fmt.Errorf("evidence pack: pdf font %s: %w", f.name, err)
		}
	}
	return &pdfDoc{pdf: pdf, total: total, header: header, sections: map[string]int{}}, nil
}

func (d *pdfDoc) fail(err error) {
	if err != nil && d.err == nil {
		d.err = fmt.Errorf("evidence pack: pdf: %w", err)
	}
}

func (d *pdfDoc) setFont(f face, size float64) {
	if d.font == f && d.size == size {
		return
	}
	d.fail(d.pdf.SetFont(string(f), "", size))
	d.font, d.size = f, size
}

func (d *pdfDoc) width(f face, size float64, s string) float64 {
	d.setFont(f, size)
	w, err := d.pdf.MeasureTextWidth(s)
	d.fail(err)
	return w
}

func (d *pdfDoc) fill(c rgb)   { d.pdf.SetFillColor(c.r, c.g, c.b) }
func (d *pdfDoc) stroke(c rgb) { d.pdf.SetStrokeColor(c.r, c.g, c.b) }

func (d *pdfDoc) rect(x, y, w, h float64, c rgb) {
	d.fill(c)
	d.pdf.RectFromUpperLeftWithStyle(x, y, w, h, "F")
}

// hline draws a solid rule.
func (d *pdfDoc) hline(x1, x2, y, width float64, c rgb) {
	d.stroke(c)
	d.pdf.SetLineWidth(width)
	d.pdf.SetLineType("solid")
	d.pdf.Line(x1, y, x2, y)
}

func (d *pdfDoc) dashedLine(x1, y1, x2, y2, width float64) {
	d.stroke(ink)
	d.pdf.SetLineWidth(width)
	d.pdf.SetCustomLineType([]float64{1.2, 0.8}, 0)
	d.pdf.Line(x1, y1, x2, y2)
	d.pdf.SetLineType("solid")
}

// put draws one string with its top-left corner at x, y.
func (d *pdfDoc) put(x, y float64, f face, size float64, c rgb, s string) {
	d.setFont(f, size)
	d.pdf.SetTextColor(c.r, c.g, c.b)
	d.pdf.SetXY(x, y)
	d.fail(d.pdf.Cell(nil, s))
	d.text = append(d.text, s)
}

func lineHeight(size, leading float64) float64 { return size * ptToMM * leading }

// markW is the width a framework square takes before its text.
func markW(size float64) float64 { return size * ptToMM * 1.07 }

// wrap breaks runs into lines no wider than w. A word wider than a line is
// broken between characters, so a sha256 or a long module source still fits.
func (d *pdfDoc) wrap(runs []run, size, w float64) [][]piece {
	var lines [][]piece
	var cur []piece
	x := 0.0
	flush := func() {
		if len(cur) > 0 {
			// A trailing space takes no room at the end of a line.
			last := &cur[len(cur)-1]
			if t := strings.TrimRight(last.text, " "); t != last.text {
				last.text, last.w = t, d.width(last.face, size, t)
			}
		}
		lines = append(lines, cur)
		cur, x = nil, 0
	}
	for _, r := range runs {
		for i, word := range splitWords(r.text) {
			p := piece{run: r}
			p.text = word
			if i > 0 {
				p.mark = nil
			}
			extra := 0.0
			if p.mark != nil {
				extra = markW(size)
			}
			p.w = d.width(p.face, size, word) + extra
			if x+p.w > w && len(cur) > 0 && strings.TrimSpace(word) != "" {
				flush()
			}
			for p.w > w && x == 0 {
				head, tail := d.breakWord(p, size, w-extra)
				hp := p
				hp.text, hp.w = head, d.width(p.face, size, head)+extra
				hp.x = 0
				cur = append(cur, hp)
				flush()
				p.text, p.mark, extra = tail, nil, 0
				p.w = d.width(p.face, size, tail)
			}
			if x == 0 && strings.TrimSpace(p.text) == "" {
				continue
			}
			p.x = x
			cur = append(cur, p)
			x += p.w
		}
	}
	if len(cur) > 0 || len(lines) == 0 {
		flush()
	}
	return lines
}

// breakWord splits the longest head of p that fits in w.
func (d *pdfDoc) breakWord(p piece, size, w float64) (head, tail string) {
	n := 1
	for i := range p.text {
		if i > 0 && d.width(p.face, size, p.text[:i]) > w {
			break
		}
		if i > 0 {
			n = i
		}
	}
	if n >= len(p.text) {
		_, n = utf8.DecodeRuneInString(p.text)
	}
	return p.text[:n], p.text[n:]
}

// splitWords splits s into words, each keeping its trailing spaces. An
// underscore, a slash or a hyphen also ends a word, so a control id or a
// module source breaks where a reader expects it.
func splitWords(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(" _/-", s[i]) >= 0 && (i+1 == len(s) || s[i+1] != ' ') {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// drawLines draws wrapped lines from x, y and returns the height used.
func (d *pdfDoc) drawLines(lines [][]piece, x, y, size, leading float64) float64 {
	lh := lineHeight(size, leading)
	pad := (lh - size*ptToMM) / 2
	for i, ln := range lines {
		ly := y + float64(i)*lh + pad
		for _, p := range ln {
			px := x + p.x
			if p.mark != nil {
				s := size * ptToMM * 0.62
				d.rect(px, ly+size*ptToMM*0.3, s, s, *p.mark)
				px += markW(size)
			}
			d.put(px, ly, p.face, size, p.color, p.text)
			if p.dashed {
				uw := d.width(p.face, size, strings.TrimRight(p.text, " "))
				d.dashedLine(px, ly+size*ptToMM*1.05, px+uw, ly+size*ptToMM*1.05, rule1)
			}
		}
	}
	return float64(len(lines)) * lh
}

// para is a paragraph: runs, the size they are set in and their leading.
type para struct {
	runs    []run
	size    float64
	leading float64
}

func pp(size float64, runs ...run) para { return para{runs: runs, size: size, leading: 1.45} }

func (d *pdfDoc) paraHeight(pa para, w float64) float64 {
	return float64(len(d.wrap(pa.runs, pa.size, w))) * lineHeight(pa.size, pa.leading)
}

// flow draws a paragraph that may break across pages, line by line.
func (d *pdfDoc) flow(pa para, x, w, after float64) {
	lh := lineHeight(pa.size, pa.leading)
	for _, ln := range d.wrap(pa.runs, pa.size, w) {
		d.ensure(lh)
		d.y += d.drawLines([][]piece{ln}, x, d.y, pa.size, pa.leading)
	}
	d.y += after
}

// ensure starts a new page when h does not fit on this one.
func (d *pdfDoc) ensure(h float64) {
	if d.y+h > bodyEnd {
		d.newPage()
	}
}

// newPage starts a page with the running header and the footer.
func (d *pdfDoc) newPage() {
	d.pdf.AddPage()
	d.page++
	d.font = ""
	total := d.total
	if total == 0 {
		total = d.page
	}
	const hy, fy, small = 12.5, pageH - 15, 7.5
	hd, base := d.header, d.header
	for base != "" && d.width(bold, small, hd) > contentW-50 {
		_, n := utf8.DecodeLastRuneInString(base)
		base = base[:len(base)-n]
		hd = base + "..."
	}
	d.put(marginX, hy, bold, small, ink2, hd)
	right := "ctfkit by compliance.tf"
	d.put(pageW-marginX-d.width(bold, small, right), hy, bold, small, ink2, right)
	d.put(marginX, fy, sans, 7, ink2, Notice)
	num := fmt.Sprintf("Page %d of %d", d.page, total)
	d.put(pageW-marginX-d.width(bold, 7, num), fy, bold, 7, ink, num)
	d.y = bodyTop
}

// tcell is the content of one table tcell: paragraphs stacked top to bottom.
type tcell []para

type table struct {
	head    []tcell
	widths  []float64 // fractions of the content width
	rows    [][]tcell
	topRule bool // a 2px rule above the first row, for a table with no head
}

func (d *pdfDoc) colWidths(t table) []float64 {
	out := make([]float64, len(t.widths))
	for i, f := range t.widths {
		out[i] = f * contentW
	}
	return out
}

func (d *pdfDoc) rowHeight(c []tcell, widths []float64, pad float64) float64 {
	h := 0.0
	for i, cl := range c {
		ch := 0.0
		for _, pa := range cl {
			ch += d.paraHeight(pa, widths[i]-cellPadX)
		}
		h = max(h, ch)
	}
	return h + 2*pad
}

// tableStart is the height of the head and the first row: what a heading
// keeps on its page so it is never stranded.
func (d *pdfDoc) tableStart(t table) float64 {
	w := d.colWidths(t)
	h := 0.0
	if t.head != nil {
		h += d.rowHeight(t.head, w, 0) + 1.6 + rule2
	}
	if len(t.rows) > 0 {
		h += d.rowHeight(t.rows[0], w, cellPadY)
	}
	return h
}

func (d *pdfDoc) drawRow(c []tcell, widths []float64, y, pad float64) {
	x := marginX
	for i, cl := range c {
		cy := y + pad
		for _, pa := range cl {
			lines := d.wrap(pa.runs, pa.size, widths[i]-cellPadX)
			cy += d.drawLines(lines, x, cy, pa.size, pa.leading)
		}
		x += widths[i]
	}
}

func (d *pdfDoc) drawHead(t table, widths []float64) {
	h := d.rowHeight(t.head, widths, 0)
	d.drawRow(t.head, widths, d.y, 0)
	d.y += h + 1.6
	d.hline(marginX, marginX+contentW, d.y, rule2, ink)
	d.y += rule2
}

// drawTable draws a table that breaks between rows, repeating its head on
// every page it continues on. shortcut: a row taller than a whole page runs
// past the footer; split rows if a tcell ever holds that much text.
func (d *pdfDoc) drawTable(t table, after float64) {
	widths := d.colWidths(t)
	d.ensure(d.tableStart(t))
	if t.head != nil {
		d.drawHead(t, widths)
	} else if t.topRule {
		d.hline(marginX, marginX+contentW, d.y, rule2, ink)
		d.y += rule2
	}
	for _, r := range t.rows {
		h := d.rowHeight(r, widths, cellPadY)
		if d.y+h > bodyEnd {
			d.newPage()
			if t.head != nil {
				d.drawHead(t, widths)
			} else if t.topRule {
				d.hline(marginX, marginX+contentW, d.y, rule2, ink)
				d.y += rule2
			}
		}
		d.drawRow(r, widths, d.y, cellPadY)
		d.y += h
		d.hline(marginX, marginX+contentW, d.y, rule1, grey)
	}
	d.y += after
}
