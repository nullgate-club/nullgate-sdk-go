package main

import (
	"net/url"
	"reflect"
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

func TestDocumentCookiesKeepTransportAndScriptVisibilitySeparate(t *testing.T) {
	jar, err := newDocumentCookies()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse("https://page.example.test/form")
	if err != nil {
		t.Fatal(err)
	}
	hidden := &http.Cookie{Name: "session", Value: "server-only", Path: "/", HttpOnly: true}
	jar.SetCookies(endpoint, []*http.Cookie{
		hidden,
		{Name: "bm_so", Value: "visible", Path: "/", Secure: true},
		{Name: "other_path", Value: "out-of-scope", Path: "/private"},
	})
	if got := cookies(jar, endpoint.String()); !reflect.DeepEqual(got, map[string]string{"bm_so": "visible"}) {
		t.Fatalf("script-visible snapshot: %#v", got)
	}
	if hidden.MaxAge != 0 {
		t.Fatal("projection mutated the transport cookie")
	}
	transport := make(map[string]string)
	for _, cookie := range jar.Cookies(endpoint) {
		transport[cookie.Name] = cookie.Value
	}
	if !reflect.DeepEqual(transport, map[string]string{"session": "server-only", "bm_so": "visible"}) {
		t.Fatalf("transport lost a valid HttpOnly cookie: %#v", transport)
	}
	jar.SetCookies(endpoint, []*http.Cookie{{Name: "bm_so", Value: "now-private", Path: "/", HttpOnly: true}})
	if got := cookies(jar, endpoint.String()); len(got) != 0 {
		t.Fatalf("stale visible value survived HttpOnly replacement: %#v", got)
	}
	jar.SetCookies(endpoint, []*http.Cookie{{Name: "bm_so", Value: "visible-again", Path: "/"}})
	if got := cookies(jar, endpoint.String()); !reflect.DeepEqual(got, map[string]string{"bm_so": "visible-again"}) {
		t.Fatalf("visible replacement was not projected: %#v", got)
	}
}
