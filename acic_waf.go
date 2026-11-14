package nullgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	acicparse "github.com/nullgate-club/nullgate-sdk-go/v2/internal/acic"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var wafAssign = regexp.MustCompile(`\bwafInputProperties\s*=\s*Object\s*\.\s*assign\s*\(`)
var wafMarker = regexp.MustCompile(`\bwafInputProperties\s*=`)
var wafSuffix = regexp.MustCompile(`^\s*,\s*wafOnLoadProperty\s*\)`)

func DiscoverAcicWaf(rawURL, htmlText string) (*AcicWafSetup, error) {
	pageURL, err := secureURL(rawURL, nil)
	if err != nil {
		return nil, err
	}
	d, err := acicparse.Page(htmlText)
	if err != nil {
		return nil, err
	}
	var sources, assignments []string
	marker := false
	for _, src := range d.Sources {
		u, e := url.Parse(src)
		if e == nil && strings.HasSuffix(u.Path, "/captcha.js") {
			sources = append(sources, src)
		}
	}
	for _, script := range d.Scripts {
		if wafMarker.MatchString(script) {
			marker = true
		}
		for _, m := range wafAssign.FindAllStringIndex(script, -1) {
			assignments = append(assignments, strings.TrimSpace(script[m[1]:]))
		}
	}
	if len(sources) == 0 && !marker {
		return nil, nil
	}
	if len(sources) != 1 || len(assignments) != 1 {
		return nil, errors.New("malformed or ambiguous WAF view")
	}
	script, err := secureURL(sources[0], pageURL)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(script.Hostname())
	if !(host == "captcha.awswaf.com" || strings.HasSuffix(host, ".captcha.awswaf.com")) || !strings.HasSuffix(script.Path, "/captcha.js") || script.RawQuery != "" || script.ForceQuery {
		return nil, errors.New("invalid WAF provider URL")
	}
	source := assignments[0]
	end, err := acicparse.ObjectEnd(source)
	if err != nil || !wafSuffix.MatchString(source[end:]) {
		return nil, errors.New("malformed WAF properties")
	}
	raw := source[:end]
	var props map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &props) != nil || props == nil {
		return nil, errors.New("malformed WAF properties")
	}
	entries, err := acicparse.SplitTop(raw[1:len(raw)-1], ',')
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		parts, e := acicparse.SplitTop(entry, ':')
		if e != nil || len(parts) < 2 {
			return nil, errors.New("malformed WAF property")
		}
		var key string
		if json.Unmarshal([]byte(strings.TrimSpace(parts[0])), &key) != nil || seen[key] {
			return nil, errors.New("ambiguous WAF property")
		}
		seen[key] = true
	}
	locale, err := required(props, "defaultLocale")
	if err != nil {
		return nil, err
	}
	problem, err := required(props, "problem")
	if err != nil {
		return nil, err
	}
	id, err := required(props, "id")
	if err != nil {
		return nil, err
	}
	var rounds int
	if json.Unmarshal(props["visualSolutionsRequired"], &rounds) != nil || rounds < 1 {
		return nil, errors.New("invalid WAF round count")
	}
	locale = strings.ToLower(locale)
	provider := origin(script) + strings.TrimSuffix(script.EscapedPath(), "/captcha.js")
	q := url.Values{"kind": {"visual"}, "domain": {pageURL.Hostname()}, "locale": {locale}, "problem": {problem}, "num_solutions_required": {strconv.Itoa(rounds)}, "id": {id}}
	return &AcicWafSetup{ProblemURL: provider + "/problem?" + q.Encode(), Locale: locale, RoundsRequired: rounds, Headers: map[string]string{"Origin": origin(pageURL), "Referer": origin(pageURL) + "/", "Content-Type": "text/plain;charset=UTF-8"}, provider: provider}, nil
}
func (w *AcicWafSetup) VerificationURL(problem json.RawMessage) (string, error) {
	var p map[string]json.RawMessage
	if json.Unmarshal(problem, &p) != nil || p == nil {
		return "", errors.New("invalid WAF problem")
	}
	var region string
	if v, ok := p["region"]; ok && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		if json.Unmarshal(v, &region) != nil {
			return "", errors.New("invalid WAF region")
		}
	}
	u := w.provider + "/verify"
	if region != "" {
		u += "?" + url.Values{"region": {region}}.Encode()
	}
	return u, nil
}

// Challenge prepares the WAF problem request without performing network I/O.
func (w *AcicWafSetup) Challenge() *AcicRequest {
	return &AcicRequest{Role: "waf-challenge", URL: w.ProblemURL, Method: "GET", Headers: w.Headers}
}

// Verify prepares a WAF verification request from a caller-built JSON body.
func (w *AcicWafSetup) Verify(problem, body json.RawMessage) (*AcicRequest, error) {
	u, err := w.VerificationURL(problem)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid WAF verification body")
	}
	return &AcicRequest{Role: "waf-verify", URL: u, Method: "POST", Headers: w.Headers, Body: body}, nil
}

// Voucher extracts a voucher or the next problem from an AWS verification response.
func (w *AcicWafSetup) Voucher(response json.RawMessage) (string, json.RawMessage, error) {
	var p struct {
		Voucher string          `json:"captcha_voucher"`
		Success bool            `json:"success"`
		Problem json.RawMessage `json:"problem"`
	}
	if json.Unmarshal(response, &p) != nil {
		return "", nil, errors.New("invalid WAF response")
	}
	if p.Voucher != "" {
		return p.Voucher, nil, nil
	}
	var next map[string]json.RawMessage
	if !p.Success || json.Unmarshal(p.Problem, &next) != nil || next == nil {
		return "", nil, errors.New("WAF answer rejected")
	}
	return "", p.Problem, nil
}
