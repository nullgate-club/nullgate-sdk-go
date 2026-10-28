package nullgate_test

import (
	"reflect"
	"strings"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestDiscoveryRetainsPixelAmbiguityAndProvenance(t *testing.T) {
	html := `<script>bazadebezolkohpepadr="123"; bazadebezolkohpepadr='456'; bazadebezolkohpepadr="123";</script>` + "\n" +
		`<script src="/akam/13/ab?x=1&amp;y=2#drop"></script>` + "\n" +
		`<script src="/akam/13/ab?x=1&amp;y=2#drop"></script>`
	page := nullgate.Page{URL: "https://target.example/login", HTML: html}
	found, err := nullgate.FindProtections(page)
	if err != nil {
		t.Fatal(err)
	}
	expected := []struct {
		challenge string
		tag, line int
	}{{"123", 1, 2}, {"456", 1, 2}, {"123", 2, 3}, {"456", 2, 3}}
	if len(found) != len(expected) {
		t.Fatalf("wanted both challenge choices for each occurrence, got %d candidates", len(found))
	}
	for i, want := range expected {
		p, ok := found[i].(nullgate.Pixel)
		if !ok {
			t.Fatalf("candidate %d has type %T", i, found[i])
		}
		if p.Page != page || p.ScriptURL != "https://target.example/akam/13/ab?x=1&y=2" || p.Challenge != want.challenge {
			t.Errorf("candidate %d lost document, raw query, or challenge", i)
		}
		if p.Provenance == nil || *p.Provenance != (nullgate.ScriptReference{RawSource: "/akam/13/ab?x=1&y=2#drop", TagIndex: want.tag, Line: want.line, Column: 0}) {
			t.Errorf("candidate %d has incorrect source provenance", i)
		}
		needle := `bazadebezolkohpepadr="123"`
		if want.challenge == "456" {
			needle = `bazadebezolkohpepadr='456'`
		}
		if p.ChallengeOffset == nil || *p.ChallengeOffset != strings.Index(html, needle) {
			t.Errorf("candidate %d did not retain the first challenge occurrence", i)
		}
	}
}

func TestDiscoveryClassicScriptAndOriginRules(t *testing.T) {
	const version = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name string
		html string
		want []string
	}{
		{"frontend assets", `<script src="/app.js?q=1"></script><script src="/app.MJS"></script><script src="/app.cjs"></script>`, []string{}},
		{"classic only", `<script type="module" src="/module"></script><script nomodule src="/legacy"></script><script type="application/json" src="/data"></script><script type="text/javascript" src="/sensor?raw=1&amp;z=2#drop"></script>`, []string{"sensor https://target.example/sensor?raw=1&z=2"}},
		{"inert sources", `<template><script src="/hidden"></script></template><noscript><script src="/other"></script></noscript><script src="/visible"></script>`, []string{"sensor https://target.example/visible"}},
		{"same origin", `<script src="https://other.example/sensor"></script><script src="http://target.example/sensor"></script><script src="https://target.example:444/sensor"></script><script src="https://TARGET.EXAMPLE:443/ok"></script>`, []string{"sensor https://TARGET.EXAMPLE:443/ok"}},
		{"first base", `<base href="/assets/"><base href="/ignored/"><script src="collect?keep=%2B#drop"></script>`, []string{"sensor https://target.example/assets/collect?keep=%2B"}},
		{"invalid base fallback", `<base href="javascript:alert(1)"><script src="collect"></script>`, []string{"sensor https://target.example/collect"}},
		{"no inline external challenge", `<script src="/external">bazadebezolkohpepadr="123"</script><script src="/akam/13/ab"></script>`, []string{"sensor https://target.example/external"}},
		{"inert challenges", `<template><script>bazadebezolkohpepadr="123"</script></template><script type="module">bazadebezolkohpepadr="456"</script><script src="/akam/13/ab"></script>`, []string{}},
		{"SBSD raw t", `<script src="/probe.js?v=` + version + `&amp;t="></script>`, []string{"sbsd https://target.example/probe.js?v=" + version + "&t="}},
		{"ambiguous v or t", `<script src="/one?v=` + version + `&amp;v=other"></script><script src="/two?v=` + version + `&amp;t=1&amp;t=2"></script>`, []string{}},
		{"raw encoded names", `<script src="/probe?v=` + version + `&amp;%74="></script>`, []string{"sbsd https://target.example/probe?v=" + version + "&%74="}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found, err := nullgate.FindProtections(nullgate.Page{URL: "https://target.example/login", HTML: test.html})
			if err != nil {
				t.Fatal(err)
			}
			actual := make([]string, 0, len(found))
			for _, p := range found {
				if p.Provider() != "akamai" {
					t.Fatalf("unexpected provider %q", p.Provider())
				}
				var source string
				switch p := p.(type) {
				case nullgate.Sensor:
					source = p.ScriptURL
				case nullgate.Sbsd:
					source = p.ScriptURL
				case nullgate.Pixel:
					source = p.ScriptURL
				}
				actual = append(actual, p.Kind()+" "+source)
			}
			if !reflect.DeepEqual(actual, test.want) {
				t.Errorf("candidates = %q, want %q", actual, test.want)
			}
		})
	}
}

func TestSBSDOnlyRawTParameterIsBlocking(t *testing.T) {
	for _, test := range []struct {
		query    string
		blocking bool
	}{
		{"v=id", false}, {"v=id&t=", true}, {"v=id&t", true}, {"v=id&t=0", true},
		{"v=id&%74=1", false}, {"v=id&at=1", false}, {"v=id#t=1", false},
	} {
		p := nullgate.Sbsd{ScriptURL: "https://target.example/probe?" + test.query}
		if p.Blocking() != test.blocking {
			t.Errorf("query %q blocking=%v, want %v", test.query, p.Blocking(), test.blocking)
		}
	}
}

func TestDiscoveryRejectsNonHTTPPage(t *testing.T) {
	for _, raw := range []string{"/relative", "javascript:alert(1)", "https:///missing-host", "https://["} {
		if _, err := nullgate.FindProtections(nullgate.Page{URL: raw, HTML: `<script src="/sensor"></script>`}); err == nil {
			t.Errorf("accepted invalid Page.URL %q", raw)
		}
	}
}

func TestDiscoveryRootScriptUsesHTTPRootPath(t *testing.T) {
	found, err := nullgate.FindProtections(nullgate.Page{
		URL:  "https://target.example/login",
		HTML: `<script src="https://target.example?keep=1"></script>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatal("absolute root URL must retain its extensionless sensor candidate")
	}
	p, ok := found[0].(nullgate.Sensor)
	if !ok || p.ScriptURL != "https://target.example?keep=1" {
		t.Error("root URL/query provenance was changed")
	}
}
