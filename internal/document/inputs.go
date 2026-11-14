package document

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

type Summary struct {
	Length        int     `json:"length"`
	Hash          string  `json:"hash"`
	Counts        *[4]int `json:"counts,omitempty"`
	Hash31        *int32  `json:"hash31,omitempty"`
	TrimmedHash31 *int32  `json:"trimmed_hash31,omitempty"`
	TrimmedLength *int    `json:"trimmed_length,omitempty"`
}

func Summarize(value string) Summary {
	encoded := make([]byte, 0, len(value)*2)
	counts := [4]int{}
	var raw, trimmed, current int32
	var length, currentLength int
	started := false
	appendUnit := func(unit uint16) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
		raw = 31*raw + int32(unit)
		if started {
			current = 31*current + int32(unit)
			currentLength++
		}
	}
	for _, r := range value {
		space := whitespace(r)
		if !space {
			started = true
		}
		units := 1
		if r > 0xffff {
			high, low := utf16.EncodeRune(r)
			appendUnit(uint16(high))
			appendUnit(uint16(low))
			units = 2
		} else {
			appendUnit(uint16(r))
		}
		if !space {
			trimmed = current
			length = currentLength
		}
		counts[0] += units
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || space) {
			counts[1] += units
		}
		lower := unicode.ToLower(r)
		if lower >= 'a' && lower <= 'z' {
			counts[2]++
		}
		if r >= '0' && r <= '9' {
			counts[3]++
		}
	}
	digest := sha256.Sum256(encoded)
	return Summary{Length: counts[0], Hash: hex.EncodeToString(digest[:]), Counts: &counts, Hash31: &raw, TrimmedHash31: &trimmed, TrimmedLength: &length}
}

func whitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	default:
		return r >= 0x2000 && r <= 0x200a
	}
}

func Attribute(node *html.Node, name string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val, true
		}
	}
	return "", false
}

func PasswordControl(node *html.Node) bool {
	typ, _ := Attribute(node, "type")
	if strings.EqualFold(strings.TrimSpace(typ), "password") {
		return true
	}
	autocomplete, _ := Attribute(node, "autocomplete")
	for _, token := range strings.Fields(strings.ToLower(autocomplete)) {
		if token == "current-password" || token == "new-password" {
			return true
		}
	}
	for _, name := range []string{"id", "name"} {
		value, _ := Attribute(node, name)
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "password" || value == "ap_password" {
			return true
		}
	}
	return false
}

func InputDocument(source string) (*html.Node, error) {
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return nil, errors.New("could not parse page HTML")
	}
	for _, node := range cascadia.QueryAll(doc, cascadia.MustCompile("input, textarea")) {
		if !PasswordControl(node) {
			continue
		}
		for _, attr := range node.Attr {
			if attr.Key == "value" && attr.Val != "" {
				return nil, errors.New("page HTML must not contain password values")
			}
		}
		if node.Data == "textarea" {
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode && child.Data != "" {
					return nil, errors.New("page HTML must not contain password values")
				}
			}
		}
	}
	for _, template := range cascadia.QueryAll(doc, cascadia.MustCompile("template")) {
		template.FirstChild, template.LastChild = nil, nil
	}
	return doc, nil
}

func InputNode(doc *html.Node, attributes map[string]string, selector *string) (*html.Node, error) {
	var candidates []*html.Node
	if selector != nil {
		compiled, err := cascadia.Compile(*selector)
		if err != nil {
			return nil, errors.New("invalid input selector")
		}
		candidates = cascadia.QueryAll(doc, compiled)
	} else {
		for _, node := range cascadia.QueryAll(doc, cascadia.MustCompile("input, textarea")) {
			match := true
			for _, name := range []string{"id", "name"} {
				if expected, ok := attributes[name]; ok {
					actual, present := Attribute(node, name)
					if !present || actual != expected {
						match = false
					}
				}
			}
			if match {
				candidates = append(candidates, node)
			}
		}
	}
	if len(candidates) != 1 || (candidates[0].Data != "input" && candidates[0].Data != "textarea") {
		return nil, errors.New("input must match exactly one input or textarea")
	}
	for _, name := range []string{"id", "name"} {
		if expected, ok := attributes[name]; ok {
			actual, present := Attribute(candidates[0], name)
			if !present || actual != expected {
				return nil, errors.New("input identity does not match the selected control")
			}
		}
	}
	return candidates[0], nil
}
