package nullgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	acicparse "github.com/nullgate-club/nullgate-sdk-go/v2/internal/acic"
)

type AcicRequest struct {
	Role, URL, Method string
	Headers           map[string]string
	Body              []byte
}
type AcicResult struct {
	ActionType        string
	ClientSideContext json.RawMessage
	SessionToken      string
}
type AcicSetup struct {
	ServiceURL, Locale, Origin string
	options, pageURL           string
	form                       *acicparse.Form
}
type AcicWafSetup struct {
	ProblemURL, Locale string
	RoundsRequired     int
	Headers            map[string]string
	provider           string
}

func secureURL(raw string, base *url.URL) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid ACIC URL")
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("ACIC URL must use HTTPS without credentials or fragment")
	}
	return u, nil
}
func origin(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if p := u.Port(); p != "" && p != "443" {
		h += ":" + p
	}
	return "https://" + h
}
func required(m map[string]json.RawMessage, key string) (string, error) {
	var s string
	if json.Unmarshal(m[key], &s) != nil || s == "" {
		return "", fmt.Errorf("invalid ACIC %s", key)
	}
	return s, nil
}

var callRE = regexp.MustCompile(`\bacic\s*\.\s*setupACIC\s*\(`)
var hostRE = regexp.MustCompile(`^prod\.([A-Za-z]+)Amazon$`)
var hosts = map[string]string{"NA": "com", "US": "com", "EU": "de", "DE": "de", "FE": "co.jp", "JP": "co.jp", "CA": "ca", "MX": "com.mx", "AT": "at", "SG": "sg", "AU": "com.au", "PL": "pl", "TR": "com.tr", "IT": "it", "AE": "ae", "GB": "co.uk", "UK": "co.uk", "SA": "sa", "IN": "in", "FR": "fr", "ES": "es", "NL": "nl", "SE": "se", "BR": "com.br", "EG": "eg"}

func DiscoverAcic(rawURL, htmlText string) (*AcicSetup, error) {
	u, err := secureURL(rawURL, nil)
	if err != nil {
		return nil, err
	}
	d, err := acicparse.Page(htmlText)
	if err != nil {
		return nil, err
	}
	var calls []string
	for _, s := range d.Scripts {
		for _, m := range callRE.FindAllStringIndex(s, -1) {
			calls = append(calls, strings.TrimSpace(s[m[1]:]))
		}
	}
	if len(calls) == 0 {
		return nil, nil
	}
	if len(calls) != 1 || len(d.Forms) > 1 {
		return nil, errors.New("ambiguous ACIC setup")
	}
	p, err := acicparse.Properties(calls[0])
	if err != nil {
		return nil, err
	}
	vals := map[string]string{}
	for _, k := range []string{"data-ref-id", "data-locale", "data-host-config", "data-context", "data-challenge-type", "data-external-id"} {
		v, e := required(p, k)
		if e != nil {
			return nil, e
		}
		vals[k] = v
	}
	_, iframe := p["data-iframe-id"]
	_, div := p["data-div"]
	if iframe == div {
		return nil, errors.New("ACIC setup requires one mount")
	}
	if iframe {
		if _, err = required(p, "data-iframe-id"); err != nil {
			return nil, err
		}
	}
	host := ""
	for _, suffix := range hosts {
		if strings.EqualFold(u.Hostname(), "www.amazon."+suffix) {
			host = strings.ToLower(u.Hostname())
			break
		}
	}
	if host == "" {
		m := hostRE.FindStringSubmatch(vals["data-host-config"])
		if m == nil || hosts[strings.ToUpper(m[1])] == "" {
			return nil, errors.New("unsupported ACIC host config")
		}
		host = "www.amazon." + hosts[strings.ToUpper(m[1])]
	}
	options := map[string]any{"clientData": vals["data-context"], "challengeType": vals["data-challenge-type"], "locale": vals["data-locale"], "externalId": vals["data-external-id"], "enableHeaderFooter": false, "enableBypassMechanism": false, "enableModalView": false, "eventTrigger": nil, "aaExternalToken": nil, "forceJsFlush": iframe, "aamationToken": nil, "pageId": nil}
	mapping := map[string]string{"data-header-footer": "enableHeaderFooter", "data-enable-bypass-mechanism": "enableBypassMechanism", "data-enable-modal-view": "enableModalView", "data-event-trigger": "eventTrigger", "data-aa-external-token": "aaExternalToken", "data-force-js-flush": "forceJsFlush", "data-aamation-token": "aamationToken", "data-page-id": "pageId"}
	for k, target := range mapping {
		if v, ok := p[k]; ok {
			var x any
			if json.Unmarshal(v, &x) != nil {
				return nil, errors.New("invalid option")
			}
			if target == "enableHeaderFooter" || target == "enableBypassMechanism" || target == "enableModalView" || target == "forceJsFlush" {
				if _, ok := x.(bool); !ok {
					return nil, errors.New("invalid boolean option")
				}
			} else if x != nil {
				if _, ok := x.(string); !ok {
					return nil, errors.New("invalid option")
				}
			}
			options[target] = x
		}
	}
	encoded, _ := json.Marshal(options)
	s := &AcicSetup{ServiceURL: "https://" + host + "/aaut/verify/" + url.PathEscape(vals["data-ref-id"]), Locale: vals["data-locale"], Origin: origin(u), options: string(encoded), pageURL: u.String()}
	if len(d.Forms) > 0 {
		s.form = d.Forms[0]
	}
	return s, nil
}
func ParseAcicResult(headers http.Header) (*AcicResult, error) {
	var values []string
	for k, v := range headers {
		if strings.EqualFold(k, "amz-aamation-resp") {
			values = append(values, v...)
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, errors.New("ambiguous ACIC result header")
	}
	var p map[string]json.RawMessage
	if json.Unmarshal([]byte(values[0]), &p) != nil || p == nil {
		return nil, errors.New("malformed ACIC result")
	}
	a, e := required(p, "actionType")
	if e != nil {
		return nil, e
	}
	t, e := required(p, "sessionToken")
	if e != nil {
		return nil, e
	}
	ctx, ok := p["clientSideContext"]
	if !ok {
		return nil, errors.New("missing ACIC context")
	}
	return &AcicResult{a, ctx, t}, nil
}
func (r *AcicResult) VoucherResponse(voucher string) string {
	v, _ := json.Marshal(voucher)
	b, _ := json.Marshal(map[string]string{"challengeType": r.ActionType, "data": string(v)})
	return string(b)
}
func (s *AcicSetup) prepare(r *AcicResult, response string) (*AcicRequest, error) {
	u, e := url.Parse(s.ServiceURL)
	if e != nil {
		return nil, e
	}
	context := json.RawMessage("null")
	q := url.Values{}
	if r != nil {
		if !json.Valid(r.ClientSideContext) || r.SessionToken == "" {
			return nil, errors.New("invalid ACIC result")
		}
		context = r.ClientSideContext
		u.RawPath = u.EscapedPath() + "/" + url.PathEscape(r.SessionToken)
		u.Path += "/" + r.SessionToken
		var str string
		if json.Unmarshal(context, &str) != nil {
			str = string(context)
		}
		q.Set("context", str)
		q.Set("response", response)
	}
	q.Set("options", s.options)
	u.RawQuery = q.Encode()
	body, e := json.Marshal(map[string]any{"context": context, "options": s.options, "response": response, "fwcimBlob": nil})
	if e != nil {
		return nil, e
	}
	return &AcicRequest{"acic", u.String(), "POST", map[string]string{"Content-Type": "application/json", "Origin": s.Origin, "Referer": s.pageURL}, body}, nil
}
func (s *AcicSetup) Start() (*AcicRequest, error) { return s.prepare(nil, "null") }
func (s *AcicSetup) Answer(r *AcicResult, response string) (*AcicRequest, error) {
	if r == nil {
		return nil, errors.New("invalid ACIC result")
	}
	return s.prepare(r, response)
}
func (s *AcicSetup) Continuation(r *AcicResult) (*AcicRequest, error) {
	if r == nil || r.ActionType != "PASS" || r.SessionToken == "" {
		return nil, errors.New("ACIC continuation requires PASS")
	}
	if s.form == nil || !strings.EqualFold(s.form.Method, "post") {
		return nil, errors.New("ACIC continuation form missing or not POST")
	}
	base, e := secureURL(s.pageURL, nil)
	if e != nil {
		return nil, e
	}
	u, e := secureURL(s.form.Action, base)
	if e != nil || origin(u) != s.Origin {
		return nil, errors.New("ACIC continuation must be same-origin HTTPS")
	}
	var fields []string
	found := false
	for _, f := range s.form.Fields {
		value := f.Value
		if f.Name == "cvf_aamation_response_token" {
			value = r.SessionToken
			found = true
		}
		fields = append(fields, url.QueryEscape(f.Name)+"="+url.QueryEscape(value))
	}
	if !found {
		return nil, errors.New("missing ACIC token field")
	}
	return &AcicRequest{"acic-continuation", u.String(), "POST", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": s.Origin, "Referer": s.pageURL}, []byte(strings.Join(fields, "&"))}, nil
}
