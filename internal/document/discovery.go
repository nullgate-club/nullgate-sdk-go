package document

import (
	"net"
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

type Candidate struct {
	Kind, URL, Challenge string
}

type scriptSource struct {
	raw     string
	classic bool
}

type Discovery struct {
	Candidates []Candidate
	Challenges []string
	PixelURLs  []string
}

func Discover(pageURL, source string) Discovery {
	document, err := url.Parse(pageURL)
	if err != nil {
		return Discovery{}
	}
	sources, challenges, baseHref := parseScripts(source)
	base := document
	if candidate, err := url.Parse(baseHref); err == nil {
		resolved := document.ResolveReference(candidate)
		if resolved.Scheme == "http" || resolved.Scheme == "https" {
			base = resolved
		}
	}
	result := Discovery{Challenges: challenges}
	for _, reference := range sources {
		relative, err := url.Parse(reference.raw)
		if err != nil {
			continue
		}
		script := base.ResolveReference(relative)
		if script.Hostname() == "" || script.User != nil || (script.Scheme != "http" && script.Scheme != "https") {
			continue
		}
		host, err := idna.Lookup.ToASCII(script.Hostname())
		if err != nil {
			continue
		}
		host = strings.ToLower(host)
		port := script.Port()
		if port == "80" && script.Scheme == "http" || port == "443" && script.Scheme == "https" {
			port = ""
		}
		if port != "" {
			script.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			script.Host = "[" + host + "]"
		} else {
			script.Host = host
		}
		script.Fragment, script.RawFragment = "", ""
		if script.Path == "" {
			script.Path = "/"
		}
		scriptURL := script.String()
		if isThreatMetrixTags(script) {
			result.Candidates = append(result.Candidates, Candidate{Kind: "profile", URL: scriptURL})
			continue
		}
		if !reference.classic || !sameOrigin(document, script) {
			continue
		}
		if pixelPath.MatchString(script.Path) {
			result.PixelURLs = append(result.PixelURLs, scriptURL)
			for _, challenge := range challenges {
				result.Candidates = append(result.Candidates, Candidate{Kind: "pixel", URL: scriptURL, Challenge: challenge})
			}
			continue
		}
		versions, tParams := 0, 0
		isSbsd := false
		for part := range strings.SplitSeq(script.RawQuery, "&") {
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
				result.Candidates = append(result.Candidates, Candidate{Kind: "sbsd", URL: scriptURL})
			}
			continue
		}
		path := strings.ToLower(script.Path)
		if path != "" && !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".mjs") && !strings.HasSuffix(path, ".cjs") {
			result.Candidates = append(result.Candidates, Candidate{Kind: "sensor", URL: scriptURL})
		}
	}
	return result
}

func isThreatMetrixTags(source *url.URL) bool {
	if source.Hostname() == "" || source.User != nil ||
		(source.Scheme != "http" && source.Scheme != "https") ||
		!strings.HasSuffix(source.Path, "/tags.js") {
		return false
	}
	query, err := url.ParseQuery(source.RawQuery)
	if err != nil {
		return false
	}
	for _, name := range []string{"org_id", "session_id"} {
		values := query[name]
		if len(values) != 1 || values[0] == "" {
			return false
		}
	}
	return true
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
	return strings.EqualFold(a.Scheme, b.Scheme) && host(a) == host(b) && port(a) == port(b)
}

func parseScripts(source string) ([]scriptSource, []string, string) {
	z := html.NewTokenizer(strings.NewReader(source))
	var references []scriptSource
	var challenges []string
	seenChallenges := make(map[string]bool)
	var inert []string
	var base string
	baseSet, inline := false, false
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			break
		}
		raw := string(z.Raw())
		token := z.Token()
		switch kind {
		case html.StartTagToken, html.SelfClosingTagToken:
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
					if inline || (!noModule && typeValue == "module") {
						if src := strings.TrimSpace(attributes["src"]); src != "" {
							references = append(references, scriptSource{raw: src, classic: inline})
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
						challenges = append(challenges, value)
					}
				}
			}
		}
	}
	return references, challenges, base
}
