package nullgate_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
)

// A moved continuation must recover its retained sensor script without leaking input values.
func TestSensorRetentionRecoveryAndPrivacy(t *testing.T) {
	bodies := make(chan map[string]any, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		bodies <- body
		if _, retained := body["script_digest"]; retained {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"code":"script_required","message":"script required","request_id":"retry"}`)
			return
		}
		io.WriteString(w, `{"session":"state-1","script_retained":true,"request_id":"request-1","request":{"url":"https://example.com/submit","body":"sensor","headers":{},"send_at":0}}`)
	}))
	client, err := nullgate.NewClient("ng_test", nullgate.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	session, err := client.Session(nullgate.SessionOptions{UserAgent: "test browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Page("https://example.com/", `<input id="user">`, nullgate.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := page.Inputs(map[string]string{"user": "private-value"})
	if err != nil {
		t.Fatal(err)
	}
	opts := nullgate.SensorOptions{ScriptURL: "/sensor", Script: "source", Inputs: inputs, Actions: []nullgate.Action{}}
	for range 2 {
		if _, err := page.Sensor(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	}
	first, second, recovery := <-bodies, <-bodies, <-bodies
	if _, err := page.Pixel(context.Background(), nullgate.PixelOptions{ScriptURL: "/pixel", Script: "pixel", Challenge: "123"}); err != nil {
		t.Fatal(err)
	}
	if _, err := page.Sensor(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	<-bodies
	afterPixel := <-bodies
	if afterPixel["script"] != "source" || afterPixel["script_digest"] != nil {
		t.Fatal("pixel did not invalidate retained sensor script")
	}
	if first["session"] != nil || second["session"] != "state-1" || second["script_digest"] == nil || recovery["script"] != "source" || recovery["script_digest"] != nil {
		t.Fatal("sensor continuation or script recovery failed")
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-value") {
		t.Fatal("raw input reached API")
	}
	if actions, ok := first["actions"].([]any); !ok || len(actions) != 0 {
		t.Fatal("explicit empty actions were lost")
	}
}

func TestCookieGateUsesResponseLimit(t *testing.T) {
	limit, generation, ok := nullgate.AbckCounters("x%7E2suffix%7Ey%7E3")
	if !ok || limit != 2 || generation != 3 {
		t.Fatal("cookie counters were not decoded")
	}
	if nullgate.IsEnough("x~2~y~3", 1) || !nullgate.IsEnough("x~2~y~3", 2) || nullgate.IsEnough("broken", 100) {
		t.Fatal("cookie gate ignored the response limit")
	}
}

func TestPageRejectsPasswordValuesInHTML(t *testing.T) {
	client, err := nullgate.NewClient("ng_test", nullgate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(nullgate.SessionOptions{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	for _, html := range []string{`<input type="password" value="secret">`, `<template><input type="password" value="secret"></template>`, `<textarea autocomplete="current-password">secret</textarea>`} {
		if _, err := session.Page("https://example.com/", html, nullgate.PageOptions{}); err == nil {
			t.Fatal("page accepted a password value in HTML")
		}
	}
}
