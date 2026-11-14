package akamai

import (
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
	"net/url"
	"strings"
	"unicode"
)

func resolveScript(p *browser.Page, raw string) (string, error) {
	base, err := url.Parse(p.URL())
	if err != nil {
		return "", failure("invalid_url", "Invalid page URL")
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", failure("invalid_url", "Invalid script URL")
	}
	resolved := raw
	if !ref.IsAbs() {
		resolved = base.ResolveReference(ref).String()
	}
	if _, err := api.AbsoluteHTTPURL(resolved); err != nil {
		return "", failure("invalid_url", "Invalid script URL")
	}
	return resolved, nil
}

func candidate(p *browser.Page, kind, explicit, challenge string) (document.Candidate, bool, error) {
	discovery := document.Discover(p.URL(), p.HTML())
	resolved := ""
	var err error
	if explicit != "" {
		resolved, err = resolveScript(p, explicit)
		if err != nil {
			return document.Candidate{}, false, err
		}
	}
	var candidates []document.Candidate
	if kind == "pixel" && challenge != "" {
		for _, r := range challenge {
			if !unicode.IsDigit(r) {
				return document.Candidate{}, false, failure("invalid_request", "challenge must be a nonempty decimal string")
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
		return document.Candidate{}, false, failure("ambiguous_protection", "Choose script URL from: "+strings.Join(urls, ", "))
	}
	if resolved != "" && kind != "pixel" {
		return document.Candidate{Kind: kind, URL: resolved}, true, nil
	}
	if len(unique) == 0 {
		return document.Candidate{}, false, nil
	}
	return unique[0], true, nil
}

func scriptURL(p *browser.Page, kind, explicit string) (string, error) {
	candidate, ok, err := candidate(p, kind, explicit, "")
	if err != nil {
		return "", err
	}
	if !ok {
		return "", failure("protection_not_found", "No "+kind+" script found; provide script URL")
	}
	return candidate.URL, nil
}

func pixelCandidates(p *browser.Page, explicit, challenge string) (string, string, error) {
	candidate, ok, err := candidate(p, "pixel", explicit, challenge)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", failure("protection_not_found", "No pixel script or challenge found")
	}
	return candidate.URL, candidate.Challenge, nil
}

func discoveryURL(p *browser.Page, kind string) (string, error) {
	candidate, ok, err := candidate(p, kind, "", "")
	if err != nil || !ok {
		return "", err
	}
	return candidate.URL, nil
}

// SensorURL returns the discovered sensor URL.
func SensorURL(p *browser.Page) (string, error) { return discoveryURL(p, "sensor") }

// PixelURL returns the discovered pixel URL.
func PixelURL(p *browser.Page) (string, error) { return discoveryURL(p, "pixel") }

// SbsdURL returns the discovered SBSD URL.
func SbsdURL(p *browser.Page) (string, error) { return discoveryURL(p, "sbsd") }
