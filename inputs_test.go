package nullgate

import (
	"context"
	"errors"
	"testing"
)

func TestPrepareInputsSummarizesUTF16WithoutRetainingValue(t *testing.T) {
	fields := []Input{{"id": "email", "value": "A😀9!"}}
	got := PrepareInputs(fields)[0]
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
			page := &Page{html: tc.document}
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

func TestSensorRejectsRawValuesForAnyActionType(t *testing.T) {
	page := &Page{html: `<input id="email">`, url: "https://example.com/"}
	for _, kind := range []string{"input", "click", ""} {
		_, err := page.Sensor(context.Background(), SensorOptions{ScriptURL: "https://example.com/script.js", Script: "script", Actions: []Action{{"type": kind, "value": "secret"}}})
		var validation *Error
		if !errors.As(err, &validation) || validation.Code != "invalid_actions" {
			t.Fatalf("raw value for action %q: got %v, want invalid_actions", kind, err)
		}
	}
}

func TestSensorRejectsInvalidPreparedInputsBeforeSending(t *testing.T) {
	page := &Page{html: `<input id="email">`, url: "https://example.com/"}
	valid := PrepareInputs([]Input{{"id": "email", "value": "alice"}})[0]
	badHash := valid
	badHash.Value.Hash = "alice"
	badCounts := valid
	badCounts.Value.Counts = &[4]int{5, 5, 5, 1}
	rawAttribute := valid
	rawAttribute.Attributes = map[string]string{"id": "email", "value": "alice"}
	wrongControl := valid
	wrongControl.Attributes = map[string]string{"id": "missing"}
	for name, input := range map[string]PreparedInput{
		"hash":              badHash,
		"counts":            badCounts,
		"raw attribute":     rawAttribute,
		"unmatched control": wrongControl,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := page.Sensor(context.Background(), SensorOptions{
				ScriptURL: "https://example.com/script.js",
				Script:    "script",
				Inputs:    []PreparedInput{input},
			})
			var validation *Error
			if !errors.As(err, &validation) || validation.Code != "invalid_inputs" {
				t.Fatalf("got %v, want invalid_inputs", err)
			}
		})
	}
}
