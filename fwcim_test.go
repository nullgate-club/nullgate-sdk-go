package nullgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func fwcimTestParams() FwcimParams {
	return FwcimParams{Page: Page{URL: "https://www.amazon.example/ap/signin", HTML: `<form id="signin"><input id="email" name="email"><input id="password" type="PASSWORD"><textarea id="notes"></textarea></form>`}, PerformanceTiming: map[string]int64{"navigationStart": 1700000000000}}
}

func TestFwcimInputPrivacyAndChecksum(t *testing.T) {
	params := fwcimTestParams()
	text := "canvas only"
	params.Inputs = []FwcimInput{{ID: "email", Value: "é😀", Text: &text, Geometry: &FwcimGeometry{Left: -1, Top: 2, Width: 100, Height: 20}}}
	payload, err := makeFwcimPayload(params, nil, websitePayload{})
	if err != nil {
		t.Fatal(err)
	}
	input := (*payload.Inputs)[0]
	// CESU-8 represents the supplementary character as two surrogate encodings.
	wantCRC := crc32.ChecksumIEEE([]byte{0xc3, 0xa9, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80})
	if input.Checksum != wantCRC || input.Value.Length != 3 {
		t.Fatalf("wrong summary: %+v", input)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "é😀") || strings.Contains(string(data), `"value":"`) {
		t.Fatal("raw value leaked")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["script"]; exists {
		t.Fatal("FWCIM must not include script")
	}
	if !strings.Contains(string(data), `"text":"canvas only"`) {
		t.Fatal("explicit canvas text missing")
	}
	for _, value := range []any{params, params.Inputs[0], FwcimSolution{Metadata1: "secret-metadata"}} {
		if strings.Contains(fmt.Sprintf("%+v %#v", value, value), "secret-metadata") || strings.Contains(fmt.Sprintf("%+v %#v", value, value), "canvas only") {
			t.Fatal("debug representation leaked sensitive data")
		}
	}
}

func TestFwcimRejectsPasswordAndAmbiguousObservations(t *testing.T) {
	cases := []struct {
		name, html string
		field      FwcimInput
	}{
		{"password by id", `<input id="field" type="password">`, FwcimInput{ID: "field", Value: "secret"}},
		{"password by selector", `<input name="field" type="PASSWORD">`, FwcimInput{Selector: `[name=field]`, Value: "secret"}},
		{"HTML password", `<input type="password" value="secret">`, FwcimInput{ID: "other"}},
		{"ambiguous", `<input id="field"><input id="field">`, FwcimInput{ID: "field"}},
		{"identity mismatch", `<input id="field" name="actual">`, FwcimInput{ID: "field", Name: "wrong", Selector: "#field"}},
		{"noncontrol", `<div id="field"></div>`, FwcimInput{Selector: "#field"}},
		{"invalid selector", `<input id="field">`, FwcimInput{Selector: "["}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			params := fwcimTestParams()
			params.Page.HTML = test.html
			params.Inputs = []FwcimInput{test.field}
			_, err := makeFwcimPayload(params, nil, websitePayload{})
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("expected non-echoing validation error")
			}
		})
	}
	params := fwcimTestParams()
	for _, html := range []string{
		`<input type=password value=secret>`,
		`<input type=password value="" value="secret">`,
		`<input type=password value="secret" value="">`,
		`<input type=password value="" value="&#115;ecret" value="">`,
	} {
		params.Page.HTML = html
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
			t.Fatal("HTML passwords must fail even without input observations")
		}
	}
	params.Page.HTML = `<input id="field"><input id="field"><textarea id="notes"></textarea>`
	params.Inputs = []FwcimInput{{ID: "field", Selector: "input:first-child", Value: "okay"}, {ID: "notes", Value: "okay"}}
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err != nil {
		t.Fatal(err)
	}
}

func TestFwcimPresenceAndDocumentTiming(t *testing.T) {
	params := fwcimTestParams()
	first, err := makeFwcimPayload(params, nil, websitePayload{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Inputs != nil || first.Actions != nil || !first.Submitted {
		t.Fatal("omitted defaults lost")
	}
	params.Inputs, params.Actions = []FwcimInput{}, []Action{}
	no := false
	params.Submitted = &no
	second, err := makeFwcimPayload(params, nil, first.Website.websitePayload)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"inputs":[]`) || !strings.Contains(string(data), `"actions":[]`) || second.Submitted {
		t.Fatal("empty observations lost")
	}
	if second.Website.DocumentID != first.Website.DocumentID {
		t.Fatal("document changed on repeat call")
	}
	params.PerformanceTiming = map[string]int64{"navigationStart": 1700000000001}
	if _, err := makeFwcimPayload(params, nil, first.Website.websitePayload); err == nil {
		t.Fatal("changed document start accepted")
	}
	params.PerformanceTiming = nil
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
		t.Fatal("missing timing accepted")
	}
}

func TestFwcimEndpointStateAndErrorContinuation(t *testing.T) {
	var amazonStates, akamaiStates []string
	var amazonDocument string
	var observations sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observations.Lock()
		defer observations.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/v1/00000000-0000-4000-8000-000000000001/generate" || r.Header.Get("Authorization") != "Bearer ng_test" || r.Header.Get("User-Agent") != "test agent" || r.Header.Get("X-Nullgate-Error-Format") != "1" {
			t.Error("request contract mismatch")
		}
		w.Header().Set("X-Request-ID", "request-id")
		if r.URL.Query().Get("type") == "fwcim" {
			amazonStates = append(amazonStates, r.Header.Get("X-State-ID"))
			var body fwcimPayload
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Timezone == nil || *body.Timezone != "Europe/Berlin" {
				t.Error("timezone missing")
			}
			if amazonDocument != "" && amazonDocument != body.Website.DocumentID {
				t.Error("document changed")
			}
			amazonDocument = body.Website.DocumentID
			w.Header().Set("X-State-ID", "amazon-rotated")
			if len(amazonStates) == 1 {
				w.WriteHeader(422)
				_, _ = w.Write([]byte(`{"detail":"failed"}`))
				return
			}
			_, _ = w.Write([]byte(`{"metadata1":"raw+metadata/=","send_at":0,"headers":{"Accept-Language":"en-US"}}`))
		} else {
			akamaiStates = append(akamaiStates, r.Header.Get("X-State-ID"))
			w.Header().Set("X-State-ID", "akamai-rotated")
			_, _ = w.Write([]byte(`{"sensor_data":"sensor","send_at":0,"headers":{}}`))
		}
	}))
	defer server.Close()
	client, err := NewClient("ng_test", Options{AmazonBaseURL: server.URL, BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	timezone := "Europe/Berlin"
	session, err := client.Open(SessionOptions{Identity: "00000000-0000-4000-8000-000000000001", UserAgent: "test agent", Timezone: &timezone})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	params := fwcimTestParams()
	if _, err := session.Fwcim(context.Background(), params); err == nil {
		t.Fatal("expected API error")
	}
	for range 2 {
		if _, err := session.Solve(context.Background(), SensorParams{Protection: Sensor{Page: params.Page, ScriptURL: "https://example.com/sensor"}, Script: "source"}); err != nil {
			t.Fatal(err)
		}
	}
	solution, err := session.Fwcim(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if solution.Metadata1 != "raw+metadata/=" || solution.RequestID != "request-id" {
		t.Fatal("response changed")
	}
	if err := solution.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	observations.Lock()
	defer observations.Unlock()
	if amazonStates[0] == akamaiStates[0] || amazonStates[1] != "amazon-rotated" || akamaiStates[1] != "akamai-rotated" {
		t.Fatal("provider state was shared or lost")
	}
}

func TestFwcimCancellationAndProtocolValidation(t *testing.T) {
	client, err := NewClient("ng_test", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Open(SessionOptions{Identity: "00000000-0000-4000-8000-000000000001", UserAgent: "test agent"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	session.amazonGate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.Fwcim(ctx, fwcimTestParams()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-session.amazonGate
	if err := (&FwcimSolution{SendAt: 0}).Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	response := &http.Response{Header: http.Header{"X-Request-Id": []string{"request"}}}
	for _, body := range []string{
		`null`,
		`{}`,
		`{"metadata1":"x","send_at":0,"headers":{"Bad Header":"x"}}`,
		`{"metadata1":"x","send_at":0,"headers":{"X":null}}`,
		`{"metadata1":"x","send_at":0,"headers":{"Authorization":"one","authorization":"two"}}`,
	} {
		if _, err := normalizeFwcimSolution(response, []byte(body)); err == nil {
			t.Fatalf("accepted invalid response: %s", body)
		}
	}
	params := fwcimTestParams()
	params.Actions = []Action{{"type": "input", "value": "secret"}}
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("raw action accepted or echoed")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Fwcim(context.Background(), params); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestFwcimFormScopePasswordNormalizationAndTiming(t *testing.T) {
	params := fwcimTestParams()
	params.Page.HTML = `<form id="one"><input id="shared"></form><form id="two"><input id="shared"><input id="secret" type="  PaSsWoRd &#9;"></form><input id="outside">`
	params.FormSelector = "#one"
	params.Inputs = []FwcimInput{{ID: "shared", Value: "okay"}}
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"[", "form", "#outside", "#missing"} {
		bad := params
		bad.FormSelector = selector
		if _, err := makeFwcimPayload(bad, nil, websitePayload{}); err == nil {
			t.Errorf("accepted invalid form selection %q", selector)
		}
	}
	for _, field := range []FwcimInput{{ID: "outside"}, {Selector: "#outside"}} {
		bad := params
		bad.Inputs = []FwcimInput{field}
		if _, err := makeFwcimPayload(bad, nil, websitePayload{}); err == nil {
			t.Fatal("accepted observation outside selected form")
		}
	}
	params.FormSelector = "#two"
	params.Inputs = []FwcimInput{{ID: "secret", Value: "private"}}
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
		t.Fatal("accepted whitespace-normalized password observation")
	}
	params.Inputs = nil
	params.Page.HTML += `<input type=" PASSWORD " value="private">`
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
		t.Fatal("password guard was scoped to selected form")
	}
	params = fwcimTestParams()
	for _, timestamp := range []int64{0, 1700000000000, 1700000000001, 1699999999999} {
		params.PerformanceTiming["loadEventEnd"] = timestamp
		_, err := makeFwcimPayload(params, nil, websitePayload{})
		if (err == nil) != (timestamp == 0 || timestamp >= params.PerformanceTiming["navigationStart"]) {
			t.Errorf("wrong timing decision for %d: %v", timestamp, err)
		}
	}
}

func TestFwcimActionNestedShapes(t *testing.T) {
	valid := []Action{
		{"type": "input", "target_path": "#field", "pointer_type": "", "target": 0, "trusted": nil, "x": 1.5},
		{"touches": []map[string]any{{"x": -1, "y": 0, "identifier": 2}}},
		{"acceleration": []any{1, nil, 2.5}, "acceleration_with_gravity": nil, "rotation_rate": [3]float64{1, 2, 3}},
		{"input_summary": []any{3, [4]int{1, 2, 3, 4}}},
		{"input_summary": []any{0, nil}},
	}
	if _, err := prepareFwcimActions(valid); err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{
		{"type": map[string]any{"value": "private"}},
		{"target_path": nil}, {"pointer_type": []string{"mouse"}},
		{"target": true}, {"target": 1.5}, {"trusted": 1}, {"x": "private"},
		{"value": "private"}, {"key": "private"}, {"text": true},
		{"touches": nil}, {"touches": []any{nil}},
		{"touches": []any{map[string]any{"x": 1, "value": "private"}}},
		{"touches": []any{map[string]any{"identifier": true}}},
		{"touches": []any{map[string]any{"x": nil, "y": 1}}},
		{"touches": []any{map[string]any{"x": 1}}},
		{"touches": []any{map[string]any{"x": 1, "y": 1, "identifier": 0.5}}},
		{"checksum": -1}, {"checksum": uint64(4294967296)}, {"checksum": 0.5},
		{"text": []string{"private"}},
		{"acceleration": map[string]any{"x": map[string]any{"value": "private"}}},
		{"rotation_rate": map[string]any{"x": 1}},
		{"acceleration": map[string]any{"x": 1, "y": 2, "z": 3}},
		{"acceleration": []any{1, 2}},
		{"acceleration_with_gravity": []any{1, 2, 3, 4}},
		{"rotation_rate": []any{1, true, 3}},
		{"rotation_rate": []any{1, "private", 3}},
		{"input_summary": map[string]any{"length": 3}},
		{"input_summary": []any{-1, nil}}, {"input_summary": []any{true, nil}},
		{"input_summary": []any{1, []any{1, 2, 3, "private"}}},
	} {
		if _, err := prepareFwcimActions([]Action{action}); err == nil || strings.Contains(err.Error(), "private") {
			t.Errorf("accepted or exposed unsafe action: %v", err)
		}
	}
}

type fwcimMarshaledNumber int

func (fwcimMarshaledNumber) MarshalJSON() ([]byte, error) {
	return []byte(`{"value":"private"}`), nil
}

type fwcimChangingNumber struct{ calls *int }

func (number fwcimChangingNumber) MarshalJSON() ([]byte, error) {
	*number.calls++
	if *number.calls == 1 {
		return []byte(`1`), nil
	}
	return []byte(`{"value":"private"}`), nil
}

func TestFwcimCapturesActualActionJSONOnce(t *testing.T) {
	for _, action := range []Action{
		nil,
		{"x": fwcimMarshaledNumber(1)},
		{"target": json.Number("9007199254740992.5")},
		{"input_summary": []any{json.Number("9007199254740992.5"), nil}},
		{"touches": []any{map[string]any{"x": 0, "y": 0, "identifier": json.Number("9007199254740992.5")}}},
	} {
		params := fwcimTestParams()
		params.Actions = []Action{action}
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("accepted unsafe serialized observation: %v", err)
		}
	}
	calls := 0
	session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(r *http.Request) (*http.Response, error) {
		var payload struct {
			Actions []Action `json:"actions"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Actions) != 1 || payload.Actions[0]["x"] != json.Number("1") || payload.Actions[0]["text"] != "audited canvas" {
			t.Fatal("validated JSON was not sent")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"X-Request-Id": {"request-id"}}, Body: io.NopCloser(strings.NewReader(`{"metadata1":"ok","send_at":0,"headers":{}}`))}, nil
	})}})
	params := fwcimTestParams()
	params.Actions = []Action{{"x": fwcimChangingNumber{&calls}, "text": "audited canvas", "checksum": uint32(4294967295)}}
	if _, err := session.Fwcim(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("custom marshal called %d times", calls)
	}
}

func TestFwcimFormDescendantScope(t *testing.T) {
	for _, test := range []struct {
		name, html, form, selector string
		valid                      bool
	}{
		{"external", `<form id="one"></form><input id="field" form="one">`, "#one", "#field", false},
		{"reassigned", `<form id="one"><input id="field" form="two"></form><form id="two"></form>`, "#one", "#field", true},
		{"empty form", `<form id="one"><input id="field" form=""></form>`, "#one", "#field", true},
		{"nonform first id", `<div id="one"></div><form id="one"></form><input id="field" form="one">`, "form", "#field", false},
		{"duplicate second", `<form id="one"></form><form id="one" class="second"><input id="field" form="one"></form>`, ".second", "#field", true},
		{"duplicate first", `<form id="one"></form><form id="one" class="second"><input id="field" form="one"></form>`, "form:first-child", "#field", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := fwcimTestParams()
			params.Page.HTML, params.FormSelector = test.html, test.form
			params.Inputs = []FwcimInput{{Selector: test.selector}}
			_, err := makeFwcimPayload(params, nil, websitePayload{})
			if (err == nil) != test.valid {
				t.Fatalf("descendant decision: %v", err)
			}
		})
	}
}

func TestFwcimPasswordAliasesAndPositiveStart(t *testing.T) {
	for _, attributes := range []string{`autocomplete="section-login CURRENT-password"`, `autocomplete="new-password"`, `id=" AP_PASSWORD "`, `name=" Password "`} {
		params := fwcimTestParams()
		params.Page.HTML = `<input ` + attributes + ` value="private">`
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
			t.Fatal("populated sensitive HTML accepted")
		}
		params.Page.HTML = `<input ` + attributes + `>`
		params.Inputs = []FwcimInput{{Selector: "input", Value: "private"}}
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
			t.Fatal("sensitive observation accepted")
		}
	}
	params := fwcimTestParams()
	params.PerformanceTiming["navigationStart"] = 0
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
		t.Fatal("zero navigation start accepted")
	}
}

func TestAmazonGenerationDoesNotBlockAkamai(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"sensor_data":"ok","send_at":0,"headers":{}}`
		if r.URL.Query().Get("type") == "fwcim" {
			close(entered)
			<-release
			body = `{"metadata1":"ok","send_at":0,"headers":{}}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"X-Request-Id": {"request-id"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}})
	amazonResult := make(chan error, 1)
	go func() { _, err := session.Fwcim(context.Background(), fwcimTestParams()); amazonResult <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := session.Solve(ctx, SensorParams{Protection: Sensor{Page: fwcimTestParams().Page, ScriptURL: "https://example.com/sensor"}, Script: "source"})
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-amazonResult; err != nil {
		t.Fatal(err)
	}
}

func TestAmazonQueuedGenerationHonorsCloseAndCancellation(t *testing.T) {
	for _, owner := range []string{"session", "client", "caller"} {
		t.Run(owner, func(t *testing.T) {
			session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(*http.Request) (*http.Response, error) {
				t.Error("queued generation issued HTTP")
				return nil, errors.New("unexpected request")
			})}})
			session.amazonGate <- struct{}{}
			defer func() { <-session.amazonGate }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := session.Fwcim(ctx, fwcimTestParams()); result <- err }()
			want := ErrClosed
			switch owner {
			case "session":
				_ = session.Close()
			case "client":
				_ = session.client.Close()
			case "caller":
				cancel()
				want = context.Canceled
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("queued generation did not stop")
			}
		})
	}
}

func TestFwcimTemplateContentIsNotADocumentDescendant(t *testing.T) {
	params := fwcimTestParams()
	params.Page.HTML = `<form id="f"><template><input id="inert"></template><input id="active"></form><template><form id="hidden"></form></template>`
	params.FormSelector = "#f"
	for _, field := range []FwcimInput{{ID: "inert"}, {Selector: "#inert"}} {
		params.Inputs = []FwcimInput{field}
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
			t.Fatal("accepted a template input")
		}
	}
	params.Inputs = []FwcimInput{{ID: "active", Value: "safe"}}
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err != nil {
		t.Fatal(err)
	}
	params.Inputs = nil
	params.FormSelector = "#hidden"
	if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
		t.Fatal("accepted a template form")
	}
	params.FormSelector = ""
	for _, html := range []string{
		`<template><input type=password value="" value=private></template>`,
		`<template><textarea autocomplete=current-password>private</textarea></template>`,
	} {
		params.Page.HTML = html
		if _, err := makeFwcimPayload(params, nil, websitePayload{}); err == nil {
			t.Fatal("template content bypassed the password guard")
		}
	}
}
