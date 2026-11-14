package amazon

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFwcimSendsPreparedObservationsAndContinuesSession(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		var source io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer reader.Close()
			source = reader
		}
		if err := json.NewDecoder(source).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"metadata1":"opaque","headers":{},"send_at":0,"session":"continued","request_id":"request"}`)
	}))
	defer server.Close()
	client, err := api.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := browser.New(browser.Options{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	product, err := New(client).Session(session)
	if err != nil {
		t.Fatal(err)
	}
	start := int64(1700000000000)
	page, err := session.Page("https://shop.example/login", `<form id="login"><input id="email" type="email"><input id="password" type="password"><input id="unicode"></form>`, browser.PageOptions{StartedAtMS: &start})
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := PrepareInputs(page, []browser.Input{{"id": "email", "value": "private@example.com"}, {"id": "password", "value": "secret"}, {"id": "unicode", "value": "😀"}})
	if err != nil {
		t.Fatal(err)
	}
	inputs[0].Geometry = &Geometry{Width: 200, Height: 20}
	opts := FwcimOptions{Form: "#login", Timing: map[string]float64{"navigationStart": float64(start)}, Inputs: inputs, Actions: []browser.Action{}, Cookies: map[string]string{"session-id": "cookie", "other": "private-cookie"}}
	for i := range 2 {
		if i == 1 {
			submitted := false
			opts.Submitted = &submitted
		}
		result, err := product.Fwcim(context.Background(), page, opts)
		if err != nil {
			t.Fatal(err)
		}
		if result.Metadata1 != "opaque" {
			t.Fatalf("unexpected metadata: %q", result.Metadata1)
		}
	}
	if len(bodies) != 2 || bodies[1]["session"] != "continued" {
		t.Fatalf("session did not continue: %#v", bodies)
	}
	if bodies[0]["submitted"] != true || bodies[1]["submitted"] != false {
		t.Fatal("submission defaults or explicit false lost")
	}
	encoded, err := json.Marshal(bodies[0])
	if err != nil {
		t.Fatal(err)
	}
	wire := string(encoded)
	for _, secret := range []string{"secret", "private-cookie"} {
		if strings.Contains(wire, secret) {
			t.Fatalf("raw private value in request: %s", secret)
		}
	}
	observed := bodies[0]["inputs"].([]any)
	email := observed[0].(map[string]any)
	password := observed[1].(map[string]any)
	unicode := observed[2].(map[string]any)
	if email["checksum"] != float64(102374657) || email["text"] != "private@example.com" || unicode["checksum"] != float64(3837346893) {
		t.Fatal("FWCIM checksum or canvas text does not match the observed value")
	}
	if _, ok := password["checksum"]; ok {
		t.Fatal("password checksum reached API")
	}
	if _, ok := password["text"]; ok {
		t.Fatal("password text reached API")
	}
	for _, field := range []string{`"geometry"`, `"actions":[]`, `"form_selector":"#login"`} {
		if !strings.Contains(wire, field) {
			t.Fatalf("missing %s in %s", field, wire)
		}
	}
}

func TestFwcimRejectsUnsafeOrInvalidObservations(t *testing.T) {
	client, err := api.New("ng_test", api.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := browser.New(browser.Options{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	product, err := New(client).Session(session)
	if err != nil {
		t.Fatal(err)
	}
	start := int64(1700000000000)
	cases := []struct {
		name, html, form string
		inputs           []browser.Input
		timing           float64
		actions          []browser.Action
	}{
		{"password in HTML", `<input type="password" value="secret">`, "", nil, float64(start), nil},
		{"duplicate controls", `<form><input id="email"><input id="email"></form>`, "", []browser.Input{{"id": "email", "value": "x"}}, float64(start), nil},
		{"outside form", `<form id="login"></form><input id="email">`, "#login", []browser.Input{{"id": "email", "value": "x"}}, float64(start), nil},
		{"wrong start", `<form></form>`, "", nil, float64(start + 1), nil},
		{"raw action value", `<form></form>`, "", nil, float64(start), []browser.Action{{"type": "click", "value": "secret"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := session.Page("https://shop.example/login", tc.html, browser.PageOptions{StartedAtMS: &start})
			if err != nil {
				if tc.name == "password in HTML" && !strings.Contains(err.Error(), "secret") {
					return
				}
				t.Fatal(err)
			}
			var inputs []Input
			if tc.inputs != nil {
				base := browser.PrepareInputs(tc.inputs)
				for _, item := range base {
					inputs = append(inputs, Input{PreparedInput: item})
				}
			}
			_, err = product.Fwcim(context.Background(), page, FwcimOptions{Form: tc.form, Timing: map[string]float64{"navigationStart": tc.timing}, Inputs: inputs, Actions: tc.actions})
			if err == nil {
				t.Fatal("invalid observation accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error exposed private value")
			}
		})
	}
}

// A waiting request must stop when its context is cancelled, rather than
// blocking behind another generation.
func TestFwcimWaitingRequestCanBeCancelled(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, `{"metadata1":"opaque","headers":{},"send_at":0,"session":"continued","request_id":"request"}`)
	}))
	defer server.Close()
	client, err := api.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	visit, err := browser.New(browser.Options{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := New(client).Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	page, err := visit.Page("https://shop.example/login", `<form></form>`, browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	opts := FwcimOptions{Timing: map[string]float64{"navigationStart": 1}}
	done := make(chan error, 1)
	go func() {
		_, err := session.Fwcim(context.Background(), page, opts)
		done <- err
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, err := session.Fwcim(ctx, page, opts)
		waiting <- err
	}()
	cancel()
	err = <-waiting
	close(release)
	if err != context.Canceled {
		t.Fatalf("waiting request returned %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
