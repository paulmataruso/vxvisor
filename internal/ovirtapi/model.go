package ovirtapi

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node is one element of the oVirt API model. The engine speaks both XML and
// JSON from the same model, so responses are built once as a Node tree and
// rendered in whichever the client accepts; request bodies are parsed into the
// same tree.
//
// XML is the canonical form (every oVirt SDK uses it):
//
//	<vm href="/ovirt-engine/api/vms/ID" id="ID"><name>x</name><disks><disk .../></disks></vm>
//
// The JSON form follows the engine's conventions: href/id become fields,
// scalars are strings (dates are epoch milliseconds), repeated or list-typed
// children become arrays keyed by the singular element name, and a list
// wrapper becomes an object holding that array ({"disks": {"disk": [...]}};
// a top-level collection renders as {"vm": [...]}).
type Node struct {
	Name string
	Href string
	ID   string
	// Attrs are extra XML attributes (rare in the model; e.g. none today).
	Text   string
	IsLeaf bool
	// Num renders a leaf as a JSON number (dates).
	Num  bool
	List bool // children are list items (always arrays in JSON)
	Kids []*Node
}

// El returns an object node.
func El(name string, kids ...*Node) *Node { return &Node{Name: name, Kids: compact(kids)} }

// ListOf returns a list wrapper (<disks>...</disks>).
func ListOf(name string, items ...*Node) *Node {
	return &Node{Name: name, List: true, Kids: compact(items)}
}

// Ref returns a reference to another object (<cluster href id/>).
func Ref(name, href, id string) *Node { return &Node{Name: name, Href: href, ID: id} }

// T returns a text leaf.
func T(name, text string) *Node { return &Node{Name: name, Text: text, IsLeaf: true} }

// B returns a boolean leaf.
func B(name string, v bool) *Node { return T(name, strconv.FormatBool(v)) }

// I returns an integer leaf.
func I(name string, v int64) *Node { return T(name, strconv.FormatInt(v, 10)) }

// D returns a date leaf.
func D(name string, t time.Time) *Node {
	if t.IsZero() {
		return nil
	}
	return &Node{Name: name, Text: t.Format("2006-01-02T15:04:05.000-07:00"), IsLeaf: true, Num: true}
}

// Link returns a <link href rel/> element.
func Link(href, rel string) *Node {
	return &Node{Name: "link", Kids: []*Node{{Name: "@rel", Text: rel, IsLeaf: true}}, Href: href}
}

// Obj sets href/id on an object node and returns it.
func (n *Node) Obj(href, id string) *Node { n.Href, n.ID = href, id; return n }

// Add appends children (nil ones are skipped).
func (n *Node) Add(kids ...*Node) *Node { n.Kids = append(n.Kids, compact(kids)...); return n }

func compact(ns []*Node) []*Node {
	out := ns[:0:0]
	for _, k := range ns {
		if k != nil {
			out = append(out, k)
		}
	}
	return out
}

// Child returns the first child named name (nil if none).
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, k := range n.Kids {
		if k.Name == name {
			return k
		}
	}
	return nil
}

// Children returns every child named name.
func (n *Node) Children(name string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, k := range n.Kids {
		if k.Name == name {
			out = append(out, k)
		}
	}
	return out
}

// Str returns the text of the child at a slash-separated path ("cpu/topology/cores").
func (n *Node) Str(path string) string {
	c := n
	for _, p := range strings.Split(path, "/") {
		if c = c.Child(p); c == nil {
			return ""
		}
	}
	return strings.TrimSpace(c.Text)
}

// Int returns Str(path) as an int64 (0 if absent/invalid).
func (n *Node) Int(path string) int64 {
	v, _ := strconv.ParseInt(n.Str(path), 10, 64)
	return v
}

// Bool returns Str(path) as a bool, with def when absent.
func (n *Node) Bool(path string, def bool) bool {
	s := n.Str(path)
	if s == "" {
		return def
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return b
}

// RefID returns the id of the child reference at path (e.g. "cluster"),
// falling back to the id at the end of its href.
func (n *Node) RefID(path string) string {
	c := n
	for _, p := range strings.Split(path, "/") {
		if c = c.Child(p); c == nil {
			return ""
		}
	}
	if c.ID != "" {
		return c.ID
	}
	if i := strings.LastIndex(c.Href, "/"); i >= 0 {
		return c.Href[i+1:]
	}
	return ""
}

// ---- XML -----------------------------------------------------------------

// XML renders the tree as an XML document.
func (n *Node) XML() []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	n.writeXML(&b)
	return b.Bytes()
}

func (n *Node) writeXML(b *bytes.Buffer) {
	b.WriteByte('<')
	b.WriteString(n.Name)
	if n.Href != "" {
		writeAttr(b, "href", n.Href)
	}
	if n.ID != "" {
		writeAttr(b, "id", n.ID)
	}
	var kids []*Node
	for _, k := range n.Kids {
		if strings.HasPrefix(k.Name, "@") {
			writeAttr(b, k.Name[1:], k.Text)
		} else {
			kids = append(kids, k)
		}
	}
	if !n.IsLeaf && len(kids) == 0 {
		b.WriteString("/>")
		return
	}
	b.WriteByte('>')
	if n.IsLeaf {
		_ = xml.EscapeText(b, []byte(n.Text))
	}
	for _, k := range kids {
		k.writeXML(b)
	}
	b.WriteString("</")
	b.WriteString(n.Name)
	b.WriteByte('>')
}

func writeAttr(b *bytes.Buffer, k, v string) {
	b.WriteByte(' ')
	b.WriteString(k)
	b.WriteString(`="`)
	_ = xml.EscapeText(b, []byte(v))
	b.WriteByte('"')
}

// ParseXML parses an XML request body into a Node tree.
func ParseXML(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(io.LimitReader(r, maxBody))
	var stack []*Node
	var root *Node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &Node{Name: t.Name.Local}
			for _, a := range t.Attr {
				switch a.Name.Local {
				case "href":
					n.Href = a.Value
				case "id":
					n.ID = a.Value
				default:
					n.Kids = append(n.Kids, &Node{Name: "@" + a.Name.Local, Text: a.Value, IsLeaf: true})
				}
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Kids = append(p.Kids, n)
			} else if root == nil {
				root = n
			}
			if len(stack) > 64 {
				return nil, errors.New("document nested too deeply")
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				n.IsLeaf = len(n.Kids) == 0 && n.Href == "" && n.ID == ""
			}
		}
	}
	if root == nil {
		return nil, errors.New("empty document")
	}
	return root, nil
}

// ---- JSON ------------------------------------------------------------------

// JSON renders the tree in the engine's JSON form. A top-level list renders
// as its inner object ({"vm": [...]}).
func (n *Node) JSON() []byte {
	var v any
	if n.List {
		v = n.jsonListBody()
	} else {
		v = n.jsonValue()
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

type orderedObj struct {
	keys []string
	vals map[string]any
}

func (o *orderedObj) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedObj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func newObj() *orderedObj { return &orderedObj{vals: map[string]any{}} }

func (n *Node) jsonValue() any {
	if n.IsLeaf {
		if n.Num {
			if t, err := time.Parse("2006-01-02T15:04:05.000-07:00", n.Text); err == nil {
				return t.UnixMilli()
			}
		}
		return n.Text
	}
	if n.List {
		return n.jsonListBody()
	}
	o := newObj()
	if n.Href != "" {
		o.set("href", n.Href)
	}
	if n.ID != "" {
		o.set("id", n.ID)
	}
	// Count names: repeated children (and links) become arrays.
	count := map[string]int{}
	for _, k := range n.Kids {
		count[k.Name]++
	}
	for _, k := range n.Kids {
		name := strings.TrimPrefix(k.Name, "@")
		if count[k.Name] > 1 || k.Name == "link" {
			arr, _ := o.vals[name].([]any)
			o.set(name, append(arr, k.jsonValue()))
			continue
		}
		o.set(name, k.jsonValue())
	}
	return o
}

func (n *Node) jsonListBody() any {
	o := newObj()
	if n.Href != "" {
		o.set("href", n.Href)
	}
	for _, k := range n.Kids {
		arr, _ := o.vals[k.Name].([]any)
		o.set(k.Name, append(arr, k.jsonValue()))
	}
	return o
}

// ParseJSON parses a JSON request body into a Node tree named root (JSON
// bodies don't carry the element name).
func ParseJSON(r io.Reader, root string) (*Node, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxBody))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	n := fromJSON(root, v, 0)
	if n == nil {
		return nil, errors.New("invalid document")
	}
	return n, nil
}

func fromJSON(name string, v any, depth int) *Node {
	if depth > 64 {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		n := &Node{Name: name}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch k {
			case "href":
				n.Href, _ = t[k].(string)
			case "id":
				n.ID = scalar(t[k])
			default:
				if arr, ok := t[k].([]any); ok {
					for _, it := range arr {
						if c := fromJSON(k, it, depth+1); c != nil {
							n.Kids = append(n.Kids, c)
						}
					}
					continue
				}
				if c := fromJSON(k, t[k], depth+1); c != nil {
					n.Kids = append(n.Kids, c)
				}
			}
		}
		return n
	case nil:
		return nil
	default:
		return &Node{Name: name, Text: scalar(t), IsLeaf: true}
	}
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

const maxBody = 8 << 20
