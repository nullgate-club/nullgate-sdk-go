package nullgate_test

import (
	"errors"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func TestPageScriptDiscovery(t *testing.T) {
	client, err := nullgate.NewClient("ng_test-key", nullgate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(nullgate.SessionOptions{UserAgent: "test browser"})
	if err != nil {
		t.Fatal(err)
	}
	const version = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		name, html, kind, want, code string
	}{
		{"no script", ``, "sensor", "", ""},
		{"base and entity", `<base href="/assets/"><script src="collect?x=1&amp;y=2#fragment"></script>`, "sensor", "https://target.example/assets/collect?x=1&y=2", ""},
		{"duplicate script", `<script src="/sensor"></script><script src="/sensor"></script>`, "sensor", "https://target.example/sensor", ""},
		{"multiple sensors", `<script src="/one"></script><script src="/two"></script>`, "sensor", "", "ambiguous_protection"},
		{"ignore inert modules and other origins", `<template><script src="/hidden"></script></template><script type="module" src="/module"></script><script src="https://other.example/a"></script><script src="/asset.js"></script>`, "sensor", "", ""},
		{"sbsd", `<script src="/probe.js?v=` + version + `&amp;t=1"></script>`, "sbsd", "https://target.example/probe.js?v=" + version + "&t=1", ""},
		{"duplicate sbsd query", `<script src="/probe?v=` + version + `&amp;v=other"></script>`, "sbsd", "", ""},
		{"pixel", `<script>bazadebezolkohpepadr="123"</script><script src="/akam/13/ab"></script>`, "pixel", "https://target.example/akam/13/ab", ""},
		{"pixel without challenge", `<script src="/akam/13/ab"></script>`, "pixel", "", ""},
		{"multiple pixel challenges", `<script>bazadebezolkohpepadr="123";bazadebezolkohpepadr="456"</script><script src="/akam/13/ab"></script>`, "pixel", "", "ambiguous_protection"},
		{"inert pixel challenge", `<template><script>bazadebezolkohpepadr="123"</script></template><script src="/akam/13/ab"></script>`, "pixel", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := session.Page("https://target.example/login", tt.html, nullgate.PageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var got string
			switch tt.kind {
			case "sensor":
				got, err = page.SensorURL()
			case "pixel":
				got, err = page.PixelURL()
			case "sbsd":
				got, err = page.SbsdURL()
			}
			if tt.code != "" {
				var ngErr *nullgate.Error
				if !errors.As(err, &ngErr) || ngErr.Code != tt.code {
					t.Fatalf("got %q, %v, want error %s", got, err, tt.code)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}
