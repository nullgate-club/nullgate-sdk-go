package akamai_test

import (
	"context"
	"errors"
	"github.com/nullgate-club/nullgate-sdk-go/v2/akamai"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"testing"
)

func setupInputTest(t *testing.T) (*akamai.Session, *browser.Page) {
	t.Helper()
	connection, err := api.New("ng_test", api.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	visit, err := browser.New(browser.Options{UserAgent: "test browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := visit.Page("https://example.com/", `<input id="email">`, browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := akamai.New(connection).Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	return session, page
}
func TestSensorRejectsRawValuesForAnyActionType(t *testing.T) {
	session, page := setupInputTest(t)
	for _, kind := range []string{"input", "click", ""} {
		_, err := session.Sensor(context.Background(), page, akamai.SensorOptions{ScriptURL: "https://example.com/script.js", Script: "script", Actions: []browser.Action{{"type": kind, "value": "secret"}}})
		var validation *api.Error
		if !errors.As(err, &validation) || validation.Code != "invalid_actions" {
			t.Fatalf("raw value for action %q: got %v, want invalid_actions", kind, err)
		}
	}
}

func TestSensorRejectsInvalidPreparedInputsBeforeSending(t *testing.T) {
	session, page := setupInputTest(t)
	valid := browser.PrepareInputs([]browser.Input{{"id": "email", "value": "alice"}})[0]
	badHash := valid
	badHash.Value.Hash = "alice"
	badCounts := valid
	badCounts.Value.Counts = &[4]int{5, 5, 5, 1}
	rawAttribute := valid
	rawAttribute.Attributes = map[string]string{"id": "email", "value": "alice"}
	wrongControl := valid
	wrongControl.Attributes = map[string]string{"id": "missing"}
	for name, input := range map[string]browser.PreparedInput{
		"hash":              badHash,
		"counts":            badCounts,
		"raw attribute":     rawAttribute,
		"unmatched control": wrongControl,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := session.Sensor(context.Background(), page, akamai.SensorOptions{
				ScriptURL: "https://example.com/script.js",
				Script:    "script",
				Inputs:    []browser.PreparedInput{input},
			})
			var validation *api.Error
			if !errors.As(err, &validation) || validation.Code != "invalid_inputs" {
				t.Fatalf("got %v, want invalid_inputs", err)
			}
		})
	}
}

// A page from another visit must never use this session's continuation.
func TestSessionRejectsPageFromAnotherVisit(t *testing.T) {
	session, _ := setupInputTest(t)
	other, err := browser.New(browser.Options{UserAgent: "other browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := other.Page("https://example.com/", "", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Sensor(context.Background(), page, akamai.SensorOptions{ScriptURL: "/sensor", Script: "source"})
	var validation *api.Error
	if !errors.As(err, &validation) || validation.Code != "invalid_request" {
		t.Fatalf("got %v, want invalid_request", err)
	}
}
