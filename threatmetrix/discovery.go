package threatmetrix

import (
	"net/url"
	"strings"

	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
)

func absoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, newError("invalid_url", "Expected an absolute HTTP(S) URL without credentials")
	}
	return u, nil
}

func profileScript(page *browser.Page, explicit string) (string, error) {
	resolved := ""
	if explicit != "" {
		base, err := url.Parse(page.URL())
		if err != nil {
			return "", newError("invalid_url", "Invalid page URL")
		}
		ref, err := url.Parse(explicit)
		if err != nil {
			return "", newError("invalid_url", "Invalid script URL")
		}
		resolved = explicit
		if !ref.IsAbs() {
			resolved = base.ResolveReference(ref).String()
		}
		if _, err = absoluteHTTPURL(resolved); err != nil {
			return "", newError("invalid_url", "Invalid script URL")
		}
	}
	var candidates []document.Candidate
	seen := make(map[document.Candidate]bool)
	for _, candidate := range document.Discover(page.URL(), page.HTML()).Candidates {
		if candidate.Kind == "profile" && (resolved == "" || candidate.URL == resolved) && !seen[candidate] {
			seen[candidate] = true
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) > 1 {
		urls := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			urls = append(urls, candidate.URL)
		}
		return "", newError("ambiguous_protection", "Choose script URL from: "+strings.Join(urls, ", "))
	}
	if resolved != "" {
		return resolved, nil
	}
	if len(candidates) == 0 {
		return "", newError("protection_not_found", "No profile script found; provide script URL")
	}
	return candidates[0].URL, nil
}
