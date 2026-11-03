package fixturepin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// node is one JSON value that keeps the key order and the raw scalar bytes of
// the document it was read from, so a manifest the registry served re-encodes
// byte for byte. encoding/json cannot do that: it sorts map keys and re-escapes
// strings.
type node struct {
	kind   byte     // '{', '[' or 's' (any scalar: string, number, true, false, null)
	raw    []byte   // the scalar's bytes as they appeared in the document
	keys   [][]byte // an object's keys, raw and quoted, in document order
	values []*node  // an object's values (parallel to keys) or an array's items
}

// parseJSON reads a document into a node tree. It returns the trailing
// whitespace after the top-level value separately so it can be put back.
func parseJSON(doc []byte) (*node, []byte, error) {
	if !json.Valid(doc) {
		return nil, nil, errors.New("not valid JSON")
	}
	p := &jsonParser{b: doc}
	n, err := p.value()
	if err != nil {
		return nil, nil, err
	}
	return n, doc[p.i:], nil
}

type jsonParser struct {
	b []byte
	i int
}

func (p *jsonParser) ws() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\n' || p.b[p.i] == '\r') {
		p.i++
	}
}

func (p *jsonParser) value() (*node, error) {
	p.ws()
	if p.i >= len(p.b) {
		return nil, errors.New("unexpected end of JSON")
	}
	switch p.b[p.i] {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		s, err := p.str()
		return &node{kind: 's', raw: s}, err
	default:
		start := p.i
		for p.i < len(p.b) && !bytes.ContainsRune([]byte(",]} \t\n\r"), rune(p.b[p.i])) {
			p.i++
		}
		return &node{kind: 's', raw: p.b[start:p.i]}, nil
	}
}

// str returns a quoted string token, quotes included. The document is already
// known to be valid JSON, so only escapes need care.
func (p *jsonParser) str() ([]byte, error) {
	start := p.i
	p.i++
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case '\\':
			p.i += 2
		case '"':
			p.i++
			return p.b[start:p.i], nil
		default:
			p.i++
		}
	}
	return nil, errors.New("unterminated string")
}

func (p *jsonParser) object() (*node, error) {
	n := &node{kind: '{'}
	p.i++
	for {
		p.ws()
		if p.b[p.i] == '}' {
			p.i++
			return n, nil
		}
		if p.b[p.i] == ',' {
			p.i++
			p.ws()
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		p.i++ // the colon
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.values = append(n.values, v)
	}
}

func (p *jsonParser) array() (*node, error) {
	n := &node{kind: '['}
	p.i++
	for {
		p.ws()
		if p.b[p.i] == ']' {
			p.i++
			return n, nil
		}
		if p.b[p.i] == ',' {
			p.i++
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		n.values = append(n.values, v)
	}
}

// encode writes the tree in the layout the registry serves manifests in:
// two-space indentation, ": " between key and value, and an empty object or
// array on one line.
func (n *node) encode() []byte {
	var b bytes.Buffer
	n.write(&b, 0)
	return b.Bytes()
}

func (n *node) write(b *bytes.Buffer, depth int) {
	indent := func(d int) {
		b.WriteByte('\n')
		for i := 0; i < d; i++ {
			b.WriteString("  ")
		}
	}
	switch n.kind {
	case 's':
		b.Write(n.raw)
	case '{':
		if len(n.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			indent(depth + 1)
			b.Write(k)
			b.WriteString(": ")
			n.values[i].write(b, depth+1)
		}
		indent(depth)
		b.WriteByte('}')
	case '[':
		if len(n.values) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, v := range n.values {
			if i > 0 {
				b.WriteByte(',')
			}
			indent(depth + 1)
			v.write(b, depth+1)
		}
		indent(depth)
		b.WriteByte(']')
	}
}

// get returns the value of key in an object, or nil.
func (n *node) get(key string) *node {
	if n == nil || n.kind != '{' {
		return nil
	}
	q := quote(key)
	for i, k := range n.keys {
		if bytes.Equal(k, q) {
			return n.values[i]
		}
	}
	return nil
}

// set replaces the value of key, or inserts it after the key named after (at
// the end when after is absent or empty).
func (n *node) set(key string, v *node, after string) {
	q := quote(key)
	for i, k := range n.keys {
		if bytes.Equal(k, q) {
			n.values[i] = v
			return
		}
	}
	at := len(n.keys)
	if after != "" {
		qa := quote(after)
		for i, k := range n.keys {
			if bytes.Equal(k, qa) {
				at = i + 1
			}
		}
	}
	n.keys = append(n.keys[:at], append([][]byte{q}, n.keys[at:]...)...)
	n.values = append(n.values[:at], append([]*node{v}, n.values[at:]...)...)
}

// text is the decoded value of a string scalar.
func (n *node) text() (string, bool) {
	if n == nil || n.kind != 's' || len(n.raw) == 0 || n.raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(n.raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func quote(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(fmt.Sprintf("encode string: %v", err)) // a Go string always encodes
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func strNode(s string) *node { return &node{kind: 's', raw: quote(s)} }

func strArray(items ...string) *node {
	n := &node{kind: '['}
	for _, s := range items {
		n.values = append(n.values, strNode(s))
	}
	return n
}
