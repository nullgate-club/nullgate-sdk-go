package nullgate

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
)

func (p *Page) resolveScript(raw string) (string, error) {
	base, err := url.Parse(p.url)
	if err != nil {
		return "", newError("invalid_url", "Invalid page URL")
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", newError("invalid_url", "Invalid script URL")
	}
	resolved := raw
	if !ref.IsAbs() {
		resolved = base.ResolveReference(ref).String()
	}
	if _, err := absoluteHTTPURL(resolved); err != nil {
		return "", newError("invalid_url", "Invalid script URL")
	}
	return resolved, nil
}

func (p *Page) candidate(kind, explicit, challenge string) (document.Candidate, bool, error) {
	discovery := document.Discover(p.url, p.html)
	resolved := ""
	var err error
	if explicit != "" {
		resolved, err = p.resolveScript(explicit)
		if err != nil {
			return document.Candidate{}, false, err
		}
	}
	var candidates []document.Candidate
	if kind == "pixel" && challenge != "" {
		for _, r := range challenge {
			if !unicode.IsDigit(r) {
				return document.Candidate{}, false, newError("invalid_request", "challenge must be a nonempty decimal string")
			}
		}
		urls := discovery.PixelURLs
		if resolved != "" {
			urls = []string{resolved}
		}
		for _, u := range urls {
			candidates = append(candidates, document.Candidate{Kind: kind, URL: u, Challenge: challenge})
		}
	} else if kind == "pixel" && resolved != "" {
		for _, value := range discovery.Challenges {
			candidates = append(candidates, document.Candidate{Kind: kind, URL: resolved, Challenge: value})
		}
	} else {
		for _, candidate := range discovery.Candidates {
			if candidate.Kind == kind && (resolved == "" || candidate.URL == resolved) {
				candidates = append(candidates, candidate)
			}
		}
	}
	unique := make([]document.Candidate, 0, len(candidates))
	seen := make(map[document.Candidate]bool, len(candidates))
	for _, candidate := range candidates {
		if !seen[candidate] {
			seen[candidate] = true
			unique = append(unique, candidate)
		}
	}
	if len(unique) > 1 {
		urls := make([]string, 0, len(unique))
		for _, candidate := range unique {
			urls = append(urls, candidate.URL)
		}
		return document.Candidate{}, false, newError("ambiguous_protection", "Choose script URL from: "+strings.Join(urls, ", "))
	}
	if resolved != "" && kind != "pixel" {
		return document.Candidate{Kind: kind, URL: resolved}, true, nil
	}
	if len(unique) == 0 {
		return document.Candidate{}, false, nil
	}
	return unique[0], true, nil
}

func (p *Page) script(kind, explicit string) (string, error) {
	candidate, ok, err := p.candidate(kind, explicit, "")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", newError("protection_not_found", "No "+kind+" script found; provide script URL")
	}
	return candidate.URL, nil
}

func (p *Page) pixelCandidates(explicit, challenge string) (string, string, error) {
	candidate, ok, err := p.candidate("pixel", explicit, challenge)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", newError("protection_not_found", "No pixel script or challenge found")
	}
	return candidate.URL, candidate.Challenge, nil
}

func (p *Page) discoveryURL(kind string) (string, error) {
	candidate, ok, err := p.candidate(kind, "", "")
	if err != nil || !ok {
		return "", err
	}
	return candidate.URL, nil
}

// SensorURL returns the discovered sensor URL, or an empty string if none exists.
func (p *Page) SensorURL() (string, error) { return p.discoveryURL("sensor") }

// PixelURL returns the discovered pixel URL, or an empty string if none exists.
func (p *Page) PixelURL() (string, error) { return p.discoveryURL("pixel") }

// SbsdURL returns the discovered SBSD URL, or an empty string if none exists.
func (p *Page) SbsdURL() (string, error) { return p.discoveryURL("sbsd") }
