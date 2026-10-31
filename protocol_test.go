package nullgate_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestMalformedSuccessIsProtocolErrorAndStillRotatesState(t *testing.T) {
	for _, test := range []struct {
		name, body string
		noID       bool
		params     nullgate.Params
	}{
		{"non JSON", "private response is not JSON", false, nil},
		{"missing request ID", `{"sensor_data":"s","send_at":0,"headers":{}}`, true, nil},
		{"missing deadline", `{"sensor_data":"s","headers":{}}`, false, nil},
		{"null deadline", `{"sensor_data":"s","send_at":null,"headers":{}}`, false, nil},
		{"string deadline", `{"sensor_data":"s","send_at":"0","headers":{}}`, false, nil},
		{"nonfinite deadline", `{"sensor_data":"s","send_at":1e999,"headers":{}}`, false, nil},
		{"missing headers", `{"sensor_data":"s","send_at":0}`, false, nil},
		{"null header value", `{"sensor_data":"s","send_at":0,"headers":{"X-Target":null}}`, false, nil},
		{"invalid header value", `{"sensor_data":"s","send_at":0,"headers":{"X-Target":"bad\r\nInjected:yes"}}`, false, nil},
		{"missing sensor", `{"send_at":0,"headers":{}}`, false, nil},
		{"null sensor", `{"sensor_data":null,"send_at":0,"headers":{}}`, false, nil},
		{"numeric sensor", `{"sensor_data":42,"send_at":0,"headers":{}}`, false, nil},
		{"missing target body", `{"url":"https://target.example/post","send_at":0,"headers":{}}`, false, nullgate.PixelParams{Protection: nullgate.Pixel{Page: page, ScriptURL: "https://target.example/akam/13/ab", Challenge: "123"}, Script: "source"}},
		{"relative target URL", `{"url":"/post","body":"encoded","send_at":0,"headers":{}}`, false, nullgate.SbsdParams{Protection: nullgate.Sbsd{Page: page, ScriptURL: "https://target.example/probe"}, Script: "source"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					w.Header().Set("X-State-ID", "rotated-despite-protocol-error")
					if !test.noID {
						w.Header().Set("X-Request-ID", "malformed-request")
					}
					fmt.Fprint(w, test.body)
					return
				}
				if r.Header.Get("X-State-ID") != "rotated-despite-protocol-error" {
					t.Error("successful HTTP response with malformed body lost its state rotation")
				}
				writeSensor(w)
			}))
			defer server.Close()
			session := sessionFor(t, clientFor(t, server))
			params := test.params
			if params == nil {
				params = nullgate.SensorParams{Protection: sensor, Script: "source"}
			}
			_, err := session.Solve(context.Background(), params)
			var protocol *nullgate.ProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("malformed response was not a protocol error: %v", err)
			}
			if !test.noID && protocol.RequestID != "malformed-request" {
				t.Error("protocol failure lost its diagnostic request ID")
			}
			if strings.Contains(fmt.Sprintf("%#v", err), "private response") {
				t.Error("protocol error rendered the response body")
			}
			if _, err := session.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissingStateHeaderRetainsAnExplicitEmptyRotation(t *testing.T) {
	states := make(chan string, 3)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header[http.CanonicalHeaderKey("X-State-ID")]; !present {
			t.Error("state header was absent")
		}
		states <- r.Header.Get("X-State-ID")
		if calls == 0 {
			w.Header().Set("X-State-ID", "")
		}
		calls++
		writeSensor(w)
	}))
	defer server.Close()
	session := sessionFor(t, clientFor(t, server))
	for range 3 {
		if _, err := session.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"}); err != nil {
			t.Fatal(err)
		}
	}
	if <-states == "" || <-states != "" || <-states != "" {
		t.Error("an explicit empty rotation was not retained after local state creation")
	}
}

func TestInvalidParamsFailBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid params reached the network")
		writeSensor(w)
	}))
	defer server.Close()
	session := sessionFor(t, clientFor(t, server))
	var nilSensor *nullgate.SensorParams
	for _, params := range []nullgate.Params{
		nil, nilSensor,
		nullgate.SensorParams{Protection: sensor},
		nullgate.SensorParams{Protection: nullgate.Sensor{Page: page, ScriptURL: "/relative"}, Script: "source"},
		nullgate.PixelParams{Protection: nullgate.Pixel{Page: page, ScriptURL: "https://target.example/akam/13/ab", Challenge: "not-decimal"}, Script: "source"},
	} {
		if _, err := session.Solve(context.Background(), params); err == nil {
			t.Errorf("accepted invalid params of type %T", params)
		}
	}
	startedAtMS := int64(0)
	for _, invalidPage := range []nullgate.Page{
		{URL: page.URL, DocumentID: identity},
		{URL: page.URL, StartedAtMS: &startedAtMS},
		{URL: page.URL, DocumentID: "not-a-uuid", StartedAtMS: &startedAtMS},
	} {
		params := nullgate.SensorParams{Protection: nullgate.Sensor{Page: invalidPage, ScriptURL: sensor.ScriptURL}, Script: "source"}
		if _, err := session.Solve(context.Background(), params); err == nil {
			t.Error("accepted an incomplete or invalid document observation")
		}
	}
}

func TestDebugOutputDoesNotExposeCallerSecrets(t *testing.T) {
	client, err := nullgate.NewClient(apiKey, nullgate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	values := []any{
		client, page, sensor,
		nullgate.SensorParams{Protection: sensor, Script: "secret-script-text", Cookies: map[string]string{"cookie": "secret-cookie"}, Inputs: []nullgate.Input{{"value": "secret-password"}}},
		nullgate.Solution{Body: "secret-solution-body", Headers: map[string]string{"Cookie": "secret-cookie"}},
		&nullgate.APIError{StatusCode: 422, Detail: "secret-script-text " + apiKey, RequestID: "diagnostic"},
		&nullgate.TransportError{Operation: "generate", Err: fmt.Errorf("underlying request contains %s", apiKey)},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, value)
			for _, secret := range []string{apiKey, page.HTML, "secret-script-text", "secret-cookie", "secret-password", "secret-solution-body"} {
				if strings.Contains(rendered, secret) {
					t.Errorf("%T exposes a secret with format %s", value, format)
				}
			}
		}
	}
}

func TestConfigurationRejectsCredentialAndHeaderInjection(t *testing.T) {
	for _, test := range []struct {
		key     string
		options nullgate.Options
	}{
		{"uuid-is-not-an-ng-key", nullgate.Options{}},
		{"ng_secret\r\nInjected: value", nullgate.Options{}},
		{apiKey, nullgate.Options{BaseURL: "/relative"}},
		{apiKey, nullgate.Options{AnalyticsURL: "https://private-user:private-password@analytics.example"}},
	} {
		if _, err := nullgate.NewClient(test.key, test.options); err == nil {
			t.Error("accepted invalid or credential-bearing API configuration")
		} else if strings.Contains(err.Error(), test.key) || strings.Contains(err.Error(), "private-password") {
			t.Error("configuration error exposed a credential")
		}
	}
	client, err := nullgate.NewClient(apiKey, nullgate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, options := range []nullgate.SessionOptions{
		{Identity: "not-a-uuid", UserAgent: "agent"},
		{Identity: identity, UserAgent: ""},
		{Identity: identity, UserAgent: "agent\r\nInjected: header"},
	} {
		if _, err := client.Open(options); err == nil {
			t.Error("accepted an invalid session identity/header")
		}
	}
}
