package browser_test

import (
	"testing"

	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
)

func TestPrepareInputsSummarizesUTF16WithoutRetainingValue(t *testing.T) {
	fields := []browser.Input{{"id": "email", "value": "A😀9!"}}
	got := browser.PrepareInputs(fields)[0]
	if got.Value.Length != 5 || got.Value.Hash != "50c42bbe0b6dd5dc9dd5c42e7b4a7a86ed413e7e808244dfc6f5ba61cb6598d4" || got.Value.Counts == nil || *got.Value.Counts != [4]int{5, 3, 1, 1} {
		t.Fatalf("unexpected input summary: %+v", got.Value)
	}
	if _, ok := got.Attributes["value"]; ok || fields[0]["value"] != "A😀9!" {
		t.Fatal("raw value retained or caller input mutated")
	}
}

func TestPageInputsBindsOnlyUniqueNonPasswordControls(t *testing.T) {
	for _, tc := range []struct {
		name, document, key string
		valid               bool
	}{
		{"id", `<input id="email">`, "email", true},
		{"name", `<textarea name="email"></textarea>`, "email", true},
		{"missing", `<input id="other">`, "email", false},
		{"duplicate", `<input name="email"><input name="email">`, "email", false},
		{"password", `<input id="email" type="password">`, "email", false},
		{"autocomplete", `<input id="email" autocomplete="new-password">`, "email", false},
		{"template", `<template><input id="email"></template>`, "email", false},
		{"html password", `<input id="email"><input type="password" value="secret">`, "email", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := browser.New(browser.Options{UserAgent: "test browser"})
			if err != nil {
				t.Fatal(err)
			}
			page, err := session.Page("https://example.com/", tc.document, browser.PageOptions{})
			if err != nil {
				if tc.valid {
					t.Fatal(err)
				}
				return
			}
			got, err := page.Inputs(map[string]string{tc.key: "alice"})
			if (err == nil) != tc.valid {
				t.Fatalf("Inputs error = %v, valid = %v", err, tc.valid)
			}
			if tc.valid && (len(got) != 1 || got[0].Value.Length != 5) {
				t.Fatalf("unexpected input summary: %+v", got)
			}
		})
	}
}
