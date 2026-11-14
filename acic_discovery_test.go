package nullgate_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	acic "github.com/nullgate-club/nullgate-sdk-go/v2"
)

const bootstrap = `<script>acic.setupACIC({'data-ref-id':'ref','data-locale':'en_US','data-host-config':'prod.NAAmazon','data-context':'a\\\'b','data-challenge-type':'POW','data-external-id':'x','data-iframe-id':'frame'});</script>`

func TestDiscoveryRejectsAmbiguityAndExpressions(t *testing.T) {
	for _, html := range []string{bootstrap + bootstrap, strings.Replace(bootstrap, "'data-ref-id':'ref'", "'data-ref-id':function(){}", 1), strings.Replace(bootstrap, "'data-ref-id':'ref'", "'data-ref-id':'x','data-ref-id':'y'", 1)} {
		if _, err := acic.DiscoverAcic("https://www.amazon.com/a", html); err == nil {
			t.Errorf("accepted malformed bootstrap %s", html)
		}
	}
}
func TestContinuationPreservesDuplicateFields(t *testing.T) {
	html := bootstrap + `<form id="cvf-aamation-challenge-form" action="../finish" method="post"><input type="hidden" name="a" value="1"><input type="hidden" name="a" value="2"><input type="hidden" name="cvf_aamation_response_token" value="old"></form>`
	s, err := acic.DiscoverAcic("https://www.amazon.com/a/start", html)
	if err != nil {
		t.Fatal(err)
	}
	r, err := acic.ParseAcicResult(http.Header{"Amz-Aamation-Resp": {`{"actionType":"PASS","sessionToken":"new","clientSideContext":null}`}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := s.Continuation(r)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "https://www.amazon.com/finish" || string(req.Body) != "a=1&a=2&cvf_aamation_response_token=new" {
		t.Fatalf("unexpected continuation: %#v", req)
	}
}
func TestAnswerKeepsEscapedContextAndVoucherNesting(t *testing.T) {
	s, err := acic.DiscoverAcic("https://www.amazon.com/", bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	r, err := acic.ParseAcicResult(http.Header{"amz-aamation-resp": {`{"actionType":"WAF","sessionToken":"a/b","clientSideContext":{"large":9007199254740993,"quote":"a\\\"b"}}`}})
	if err != nil {
		t.Fatal(err)
	}
	answer := r.VoucherResponse(`a"b`)
	req, err := s.Answer(r, answer)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u.EscapedPath(), "a%2Fb") || !strings.Contains(u.Query().Get("context"), "9007199254740993") {
		t.Fatalf("lost token or context: %s", req.URL)
	}
	var envelope map[string]string
	if err = json.Unmarshal([]byte(answer), &envelope); err != nil {
		t.Fatal(err)
	}
	var voucher string
	if json.Unmarshal([]byte(envelope["data"]), &voucher) != nil || voucher != `a"b` {
		t.Fatalf("bad voucher: %s", answer)
	}
}
func TestWafRejectsUntrustedProviderAndHandlesRounds(t *testing.T) {
	view := `<script src="https://one.captcha.awswaf.com/x/captcha.js"></script><script>const wafInputProperties = Object.assign({"defaultLocale":"EN_US","problem":"p","id":"i","visualSolutionsRequired":2}, wafOnLoadProperty);</script>`
	if _, err := acic.DiscoverAcicWaf("https://www.amazon.com/", strings.Replace(view, "one.captcha.awswaf.com", "captcha.awswaf.com.evil.test", 1)); err == nil {
		t.Fatal("accepted untrusted provider")
	}
	w, err := acic.DiscoverAcicWaf("https://www.amazon.com/", view)
	if err != nil {
		t.Fatal(err)
	}
	if w.RoundsRequired != 2 || !strings.HasPrefix(w.Challenge().URL, "https://one.captcha.awswaf.com/x/problem?") {
		t.Fatal("invalid challenge")
	}
	verify, err := w.Verify(json.RawMessage(`{"region":"a b"}`), json.RawMessage(`{"x":1}`))
	if err != nil || !strings.Contains(verify.URL, "region=a+b") {
		t.Fatalf("invalid verify: %v %v", verify, err)
	}
	voucher, next, err := w.Voucher(json.RawMessage(`{"success":true,"problem":{"state":1}}`))
	if err != nil || voucher != "" || string(next) != `{"state":1}` {
		t.Fatalf("invalid next problem: %s %s %v", voucher, next, err)
	}
	voucher, _, err = w.Voucher(json.RawMessage(`{"captcha_voucher":"v"}`))
	if err != nil || voucher != "v" {
		t.Fatal("missing voucher")
	}
}
func TestAcicResultRejectsAmbiguousHeaders(t *testing.T) {
	for _, headers := range []http.Header{{"Amz-Aamation-Resp": {`{"actionType":"PASS","sessionToken":"x"}`}}, {"Amz-Aamation-Resp": {"{}"}, "amz-aamation-resp": {"{}"}}} {
		if _, err := acic.ParseAcicResult(headers); err == nil {
			t.Fatal("accepted malformed or ambiguous result")
		}
	}
}
func TestContinuationRejectsCrossOrigin(t *testing.T) {
	html := bootstrap + `<form id="cvf-aamation-challenge-form" action="https://evil.example/submit" method="post"><input type="hidden" name="cvf_aamation_response_token"></form>`
	setup, err := acic.DiscoverAcic("https://www.amazon.com/a", html)
	if err != nil {
		t.Fatal(err)
	}
	_, err = setup.Continuation(&acic.AcicResult{ActionType: "PASS", SessionToken: "secret"})
	if err == nil {
		t.Fatal("sent token to another origin")
	}
}
