package nullgate

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/net/html"
	"golang.org/x/net/idna"
)

var pixelChallenge = regexp.MustCompile(`bazadebezolkohpepadr[\s\x{000b}\x{001c}-\x{001f}\x{0085}\p{Z}]*=[\s\x{000b}\x{001c}-\x{001f}\x{0085}\p{Z}]*(?:"([0-9]+)"|'([0-9]+)')`)
var pixelPath = regexp.MustCompile(`^/akam/13/[0-9a-fA-F]+$`)

type discoveredChallenge struct {
	value  string
	offset int
}

// FindProtections parses only the supplied HTML, without fetching or executing
// anything. Unknown .js/.mjs/.cjs frontend assets are not sensors. More than one
// candidate returns AmbiguousProtectionError by default; pass false to retain all
// occurrences and possible pixel challenges in document order. It never panics.
func FindProtections(page Page, panicOnAmbiguity ...bool) ([]Protection, error) {
	if err := validatePage(page); err != nil {
		return nil, err
	}
	document, _ := url.Parse(page.URL)
	sources, challenges, baseHref := parseScripts(page.HTML)
	base := document
	if candidate, err := url.Parse(baseHref); err == nil {
		resolved := document.ResolveReference(candidate)
		if resolved.Scheme == "http" || resolved.Scheme == "https" {
			base = resolved
		}
	}
	found := make([]Protection, 0)
	for _, reference := range sources {
		relative, err := url.Parse(reference.RawSource)
		if err != nil {
			continue
		}
		source := base.ResolveReference(relative)
		source.Fragment, source.RawFragment = "", ""
		if !sameOrigin(document, source) {
			continue
		}
		ref := reference
		if pixelPath.MatchString(source.Path) {
			for _, challenge := range challenges {
				offset := challenge.offset
				found = append(found, Pixel{
					Page: page, ScriptURL: source.String(), Challenge: challenge.value,
					Provenance: &ref, ChallengeOffset: &offset,
				})
			}
			continue
		}
		versions, tParams := 0, 0
		isSbsd := false
		for part := range strings.SplitSeq(source.RawQuery, "&") {
			name, value, _ := strings.Cut(part, "=")
			switch name {
			case "v":
				versions++
				if id, err := uuid.Parse(value); err == nil && len(value) == 36 && id.String() == strings.ToLower(value) {
					isSbsd = true
				}
			case "t":
				tParams++
			}
		}
		if isSbsd {
			if versions == 1 && tParams <= 1 {
				found = append(found, Sbsd{Page: page, ScriptURL: source.String(), Provenance: &ref})
			}
			continue
		}
		path := strings.ToLower(source.Path)
		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".mjs") && !strings.HasSuffix(path, ".cjs") {
			found = append(found, Sensor{Page: page, ScriptURL: source.String(), Provenance: &ref})
		}
	}
	if len(found) > 1 && (len(panicOnAmbiguity) == 0 || panicOnAmbiguity[0]) {
		return nil, &AmbiguousProtectionError{Count: len(found)}
	}
	return found, nil
}

// FindProtections is local even when called on a closed Client.
func (c *Client) FindProtections(page Page, panicOnAmbiguity ...bool) ([]Protection, error) {
	return FindProtections(page, panicOnAmbiguity...)
}

func sameOrigin(a, b *url.URL) bool {
	host := func(u *url.URL) string {
		name, err := idna.Lookup.ToASCII(u.Hostname())
		if err != nil {
			return strings.ToLower(u.Hostname())
		}
		return strings.ToLower(name)
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			if number, err := strconv.Atoi(p); err == nil {
				return strconv.Itoa(number)
			}
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.Scheme == b.Scheme && host(a) == host(b) && port(a) == port(b)
}

func parseScripts(source string) ([]ScriptReference, []discoveredChallenge, string) {
	z := html.NewTokenizer(strings.NewReader(source))
	var references []ScriptReference
	var challenges []discoveredChallenge
	seenChallenges := make(map[string]bool)
	var inert []string
	var base string
	baseSet, inline := false, false
	tagIndex, line, column, offset := 0, 1, 0, 0
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			break
		}
		raw := source[offset : offset+len(z.Raw())]
		token := z.Token()
		switch kind {
		case html.StartTagToken, html.SelfClosingTagToken:
			index := tagIndex
			if token.Data == "script" {
				tagIndex++
			}
			if token.Data == "template" || token.Data == "noscript" {
				inert = append(inert, token.Data)
				z.NextIsNotRawText()
			}
			if len(inert) == 0 {
				attributes := make(map[string]string, len(token.Attr))
				for _, attr := range token.Attr {
					if _, exists := attributes[attr.Key]; !exists {
						attributes[attr.Key] = attr.Val
					}
				}
				if href, exists := attributes["href"]; token.Data == "base" && !baseSet && exists {
					base, baseSet = strings.TrimSpace(href), true
				}
				if token.Data == "script" {
					typeValue := strings.ToLower(strings.TrimSpace(attributes["type"]))
					_, noModule := attributes["nomodule"]
					inline = !noModule && (typeValue == "" || typeValue == "text/javascript" || typeValue == "application/javascript")
					if inline {
						if src := strings.TrimSpace(attributes["src"]); src != "" {
							references = append(references, ScriptReference{RawSource: src, TagIndex: index, Line: line, Column: column})
						}
						if _, exists := attributes["src"]; exists {
							inline = false
						}
					}
				}
			}
			if kind == html.SelfClosingTagToken {
				if token.Data == "script" {
					z.NextIsNotRawText()
					inline = false
				}
				if len(inert) > 0 && inert[len(inert)-1] == token.Data {
					inert = inert[:len(inert)-1]
				}
			}
		case html.EndTagToken:
			if token.Data == "script" {
				inline = false
			}
			if len(inert) > 0 && inert[len(inert)-1] == token.Data {
				inert = inert[:len(inert)-1]
			}
		case html.TextToken:
			if inline && len(inert) == 0 {
				for _, match := range pixelChallenge.FindAllStringSubmatchIndex(raw, -1) {
					if match[0] > 0 {
						previous, _ := utf8.DecodeLastRuneInString(raw[:match[0]])
						if previous == '_' || unicode.IsLetter(previous) || unicode.IsNumber(previous) {
							continue
						}
					}
					start, end := match[2], match[3]
					if start < 0 {
						start, end = match[4], match[5]
					}
					value := raw[start:end]
					if !seenChallenges[value] {
						seenChallenges[value] = true
						challenges = append(challenges, discoveredChallenge{value: value, offset: offset + match[0]})
					}
				}
			}
		}
		for _, r := range raw {
			if r == '\n' {
				line++
				column = 0
			} else {
				column++
			}
		}
		offset += len(raw)
	}
	return references, challenges, base
}
