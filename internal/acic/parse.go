package acic

import (
	"encoding/json"
	"errors"
	"golang.org/x/net/html"
	"regexp"
	"strings"
)

type Field struct{ Name, Value string }
type Form struct {
	Action, Method string
	Fields         []Field
}

func attrs(n *html.Node) map[string]string {
	a := map[string]string{}
	for _, v := range n.Attr {
		if _, ok := a[v.Key]; !ok {
			a[v.Key] = v.Val
		}
	}
	return a
}

type PageData struct {
	Scripts, Sources []string
	Forms            []*Form
}

func Page(htmlText string) (PageData, error) {
	doc, err := html.Parse(strings.NewReader(htmlText))
	if err != nil {
		return PageData{}, err
	}
	var d PageData
	var walk func(*html.Node, *Form)
	walk = func(n *html.Node, f *Form) {
		if n.Type == html.ElementNode {
			a := attrs(n)
			switch n.Data {
			case "script":
				if src, ok := a["src"]; ok {
					d.Sources = append(d.Sources, src)
				} else {
					var b strings.Builder
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							b.WriteString(c.Data)
						}
					}
					d.Scripts = append(d.Scripts, b.String())
				}
			case "form":
				if a["id"] == "cvf-aamation-challenge-form" {
					f = &Form{Action: a["action"], Method: a["method"]}
					if f.Method == "" {
						f.Method = "get"
					}
					d.Forms = append(d.Forms, f)
				}
			case "input":
				if f != nil && strings.EqualFold(a["type"], "hidden") {
					_, named := a["name"]
					_, disabled := a["disabled"]
					if named && !disabled {
						f.Fields = append(f.Fields, Field{a["name"], a["value"]})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, f)
		}
	}
	walk(doc, nil)
	return d, nil
}
func SplitTop(s string, sep byte) ([]string, error) {
	var out []string
	var stack []byte
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
				if i >= len(s) {
					return nil, errors.New("malformed literal")
				}
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		switch c {
		case '(', '[', '{':
			stack = append(stack, c)
		case ')', ']', '}':
			if len(stack) == 0 || !strings.Contains("() [] {}", string([]byte{stack[len(stack)-1], c})) {
				return nil, errors.New("malformed ACIC bootstrap")
			}
			stack = stack[:len(stack)-1]
		default:
			if c == sep && len(stack) == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if quote != 0 || len(stack) != 0 {
		return nil, errors.New("malformed ACIC bootstrap")
	}
	return append(out, s[start:]), nil
}
func ObjectEnd(s string) (int, error) {
	if len(s) == 0 || s[0] != '{' {
		return 0, errors.New("invalid object")
	}
	var stack []byte
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == '\\' {
				i++
			} else if c == q {
				q = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			q = c
			continue
		}
		switch c {
		case '{', '[', '(':
			stack = append(stack, c)
		case '}', ']', ')':
			if len(stack) == 0 || !strings.Contains("{} [] ()", string([]byte{stack[len(stack)-1], c})) {
				return 0, errors.New("malformed object")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, errors.New("malformed object")
}

var propRE = regexp.MustCompile(`^\s*(?:"([^"]+)"|'([^']+)'|([\w-]+))\s*:\s*([\s\S]*)$`)

func literal(s string) (json.RawMessage, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "'") {
		var b strings.Builder
		b.WriteByte('"')
		closed := false
		for i := 1; i < len(s); i++ {
			c := s[i]
			if c == '\'' {
				if i != len(s)-1 {
					return nil, errors.New("invalid literal")
				}
				closed = true
				break
			}
			if c == '\n' || c == '\r' {
				return nil, errors.New("invalid literal")
			}
			if c == '"' {
				b.WriteString(`\"`)
			} else if c == '\\' {
				i++
				if i >= len(s) {
					return nil, errors.New("invalid literal")
				}
				c = s[i]
				if c == '\'' {
					b.WriteByte('\'')
				} else {
					b.WriteByte('\\')
					b.WriteByte(c)
				}
			} else {
				b.WriteByte(c)
			}
		}
		if !closed {
			return nil, errors.New("invalid literal")
		}
		b.WriteByte('"')
		s = b.String()
	}
	if !json.Valid([]byte(s)) {
		return nil, errors.New("unsupported ACIC literal")
	}
	return json.RawMessage(s), nil
}
func Properties(s string) (map[string]json.RawMessage, error) {
	end, err := ObjectEnd(s)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.TrimSpace(s[end:]), ")") {
		return nil, errors.New("malformed ACIC setup")
	}
	parts, err := SplitTop(s[1:end-1], ',')
	if err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		m := propRE.FindStringSubmatch(p)
		if m == nil {
			return nil, errors.New("invalid ACIC property")
		}
		key := m[1]
		if key == "" {
			key = m[2]
		}
		if key == "" {
			key = m[3]
		}
		if _, ok := out[key]; ok {
			return nil, errors.New("duplicate ACIC property")
		}
		raw := strings.TrimSpace(m[4])
		if key == "data-callback" {
			out[key] = json.RawMessage("true")
			continue
		}
		if key == "data-div" {
			if raw == "" || raw == "null" || raw == "false" || raw == "undefined" {
				return nil, errors.New("invalid ACIC mount")
			}
			out[key] = json.RawMessage("true")
			continue
		}
		if strings.HasPrefix(key, "data-") {
			v, e := literal(raw)
			if e != nil {
				return nil, e
			}
			out[key] = v
		} else {
			out[key] = json.RawMessage("null")
		}
	}
	return out, nil
}
