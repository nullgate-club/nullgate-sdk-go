package nullgate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

const identity = "550e8400-e29b-41d4-a716-446655440000"
const apiKey = "ng_test_credential_never_for_target"

var page = nullgate.Page{URL: "https://target.example/login", HTML: "<html>private original document</html>"}
var sensor = nullgate.Sensor{Page: page, ScriptURL: "https://target.example/collector?raw=1"}

func clientFor(t *testing.T, server *httptest.Server) *nullgate.Client {
	t.Helper()
	client, err := nullgate.NewClient(apiKey, nullgate.Options{BaseURL: server.URL, AnalyticsURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func sessionFor(t *testing.T, client *nullgate.Client) *nullgate.Session {
	t.Helper()
	session, err := client.Open(nullgate.SessionOptions{Identity: identity, UserAgent: "Chrome146 test agent"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func writeSensor(w http.ResponseWriter) {
	w.Header().Set("X-Request-ID", "11111111111111111111111111111111")
	fmt.Fprint(w, `{"sensor_data":"encoded-sensor","headers":{},"send_at":0}`)
}

func TestSolveBuildsOperationPayloadsAndReadyPosts(t *testing.T) {
	for _, kind := range []string{"pixel", "akamai", "sbsd"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/"+identity+"/generate" || r.URL.Query().Get("type") != kind {
					t.Errorf("wrong generate endpoint: %s %s", r.Method, r.URL)
				}
				if r.Header.Get("Authorization") != "Bearer "+apiKey || r.Header.Get("User-Agent") != "Chrome146 test agent" || r.Header.Get("Cookie") != "" {
					t.Error("generation authorization, identity headers, or cookie scoping is wrong")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if strings.Contains(string(body), "pass🔒42") {
					t.Error("raw input password crossed the API boundary")
				}
				var payload map[string]any
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(payload["website"], map[string]any{"url": page.URL, "html": page.HTML}) || payload["timezone"] != "Europe/Berlin" {
					t.Error("website or bound timezone was changed")
				}
				wantSource := sensor.ScriptURL
				if kind == "pixel" {
					wantSource = "https://target.example/akam/13/ab?original=1"
					if payload["challenge"] != "123" {
						t.Error("pixel challenge was not taken from its protection")
					}
				} else if kind == "sbsd" {
					wantSource = "https://target.example/probe?v=" + identity
				}
				if !reflect.DeepEqual(payload["script"], map[string]any{"source": wantSource, "text": "raw script source"}) {
					t.Error("source URL/query or raw script provenance was lost")
				}
				if kind == "akamai" {
					inputs := payload["inputs"].([]any)
					summary := inputs[0].(map[string]any)["value"].(map[string]any)
					if summary["hash"] != "ef58f7cdc313fe3a99cd72fee551003c739c02465323f36ac500da0148cc6824" || summary["length"] != float64(8) {
						t.Error("sensor inputs were not summarized locally with UTF-16 semantics")
					}
					if !reflect.DeepEqual(payload["cookies"], map[string]any{"bm_sz": "target-cookie"}) || !reflect.DeepEqual(payload["actions"], []any{map[string]any{"type": "mousemove", "x": float64(2)}}) {
						t.Error("sensor cookies or actions changed")
					}
				}
				w.Header().Set("X-Request-ID", "diagnostic-request-id")
				if kind == "akamai" {
					fmt.Fprint(w, `{"sensor_data":"payload\"😀","send_at":1234.5,"headers":{"content-type":"application/json","CONTENT-TYPE":"wrong","Accept-Language":"en-US"}}`)
				} else {
					fmt.Fprint(w, `{"url":"https://target.example/returned?keep=1","body":"raw=%2B&x=1","send_at":1234.5,"headers":{"Accept-Language":"en-US"}}`)
				}
			}))
			defer server.Close()
			client := clientFor(t, server)
			timezone := "Europe/Berlin"
			session, err := client.Open(nullgate.SessionOptions{Identity: identity, UserAgent: "Chrome146 test agent", Timezone: &timezone})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			timezone = "caller-mutated-timezone"
			var params nullgate.Params
			wantType := "application/x-www-form-urlencoded"
			wantURL, wantBody := "https://target.example/returned?keep=1", "raw=%2B&x=1"
			switch kind {
			case "pixel":
				params = nullgate.PixelParams{Protection: nullgate.Pixel{Page: page, ScriptURL: "https://target.example/akam/13/ab?original=1", Challenge: "123"}, Script: "raw script source"}
			case "akamai":
				params = nullgate.SensorParams{Protection: sensor, Script: "raw script source", Cookies: map[string]string{"bm_sz": "target-cookie"}, Inputs: []nullgate.Input{{"type": "password", "value": "pass🔒42"}}, Actions: []nullgate.Action{{"type": "mousemove", "x": 2}}}
				wantURL, wantBody, wantType = sensor.ScriptURL, "", "text/plain;charset=UTF-8"
			case "sbsd":
				params = &nullgate.SbsdParams{Protection: nullgate.Sbsd{Page: page, ScriptURL: "https://target.example/probe?v=" + identity}, Script: "raw script source"}
				wantType = "application/json"
			}
			solution, err := session.Solve(context.Background(), params)
			if err != nil {
				t.Fatal(err)
			}
			if solution.Method != "POST" || solution.URL != wantURL || solution.SendAt != 1234.5 || solution.RequestID != "diagnostic-request-id" {
				t.Error("solution did not preserve the actual target and diagnostic metadata")
			}
			if !reflect.DeepEqual(solution.Headers, map[string]string{"Content-Type": wantType, "Accept-Language": "en-US"}) {
				t.Errorf("target headers were not normalized: %v", solution.Headers)
			}
			if kind == "akamai" {
				var decoded map[string]string
				if err := json.Unmarshal([]byte(solution.Body), &decoded); err != nil || !reflect.DeepEqual(decoded, map[string]string{"sensor_data": "payload\"😀"}) {
					t.Error("sensor body was not encoded once as a JSON object")
				}
			} else if solution.Body != wantBody {
				t.Error("already-encoded target body was changed or double-JSON encoded")
			}
		})
	}
}

func TestSensorNilAndEmptyInputsActionsAreDifferent(t *testing.T) {
	bodies := make(chan map[string]json.RawMessage, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies <- body
		writeSensor(w)
	}))
	defer server.Close()
	session := sessionFor(t, clientFor(t, server))
	for _, params := range []nullgate.SensorParams{
		{Protection: sensor, Script: "source"},
		{Protection: sensor, Script: "source", Inputs: []nullgate.Input{}, Actions: []nullgate.Action{}},
	} {
		if _, err := session.Solve(context.Background(), params); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-bodies, <-bodies
	for _, key := range []string{"inputs", "actions"} {
		if _, exists := first[key]; exists {
			t.Errorf("nil %s must be omitted", key)
		}
		if string(second[key]) != "[]" {
			t.Errorf("empty %s must be [], not null or omitted", key)
		}
	}
	if string(first["cookies"]) != "{}" || string(second["cookies"]) != "{}" {
		t.Error("nil cookies must be the service's empty object")
	}
}

func TestRawInputAndChangeActionsFailBeforeTransport(t *testing.T) {
	client, err := nullgate.NewClient(apiKey, nullgate.Options{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("raw action input reached the transport")
			return nil, errors.New("unexpected transport call")
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := sessionFor(t, client)
	for _, kind := range []string{"input", "change"} {
		for _, raw := range []string{"private-password", ""} {
			params := nullgate.SensorParams{Protection: sensor, Script: "source", Actions: []nullgate.Action{{"type": kind, "target": 0, "value": raw}}}
			if _, err := session.Solve(context.Background(), params); err == nil {
				t.Errorf("accepted raw %s action value", kind)
			} else if strings.Contains(err.Error(), "private-password") {
				t.Error("action validation exposed private input text")
			}
		}
	}
}

func TestActionSummariesAndNullMissingValuesArePreserved(t *testing.T) {
	bodies := make(chan map[string]json.RawMessage, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies <- body
		writeSensor(w)
	}))
	defer server.Close()
	session := sessionFor(t, clientFor(t, server))
	summary := nullgate.InputValue{Length: 8, Hash: "ef58f7cdc313fe3a99cd72fee551003c739c02465323f36ac500da0148cc6824", Counts: [4]int{8, 2, 4, 2}}
	actions := []nullgate.Action{
		{"type": "input", "value": summary},
		{"type": "change", "value": summary},
		{"type": "input", "value": nil},
		{"type": "change"},
		{"type": "keypress", "value": "Enter"},
	}
	if _, err := session.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source", Actions: actions}); err != nil {
		t.Fatal(err)
	}
	want := `[{"type":"input","value":{"length":8,"hash":"ef58f7cdc313fe3a99cd72fee551003c739c02465323f36ac500da0148cc6824","counts":[8,2,4,2]}},{"type":"change","value":{"length":8,"hash":"ef58f7cdc313fe3a99cd72fee551003c739c02465323f36ac500da0148cc6824","counts":[8,2,4,2]}},{"type":"input","value":null},{"type":"change"},{"type":"keypress","value":"Enter"}]`
	var actual, expected any
	if err := json.Unmarshal((<-bodies)["actions"], &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("valid action values changed: %v", actual)
	}
}

func TestStateRotatesOnErrorsRetainsWhenAbsentAndIsolatesSessions(t *testing.T) {
	var states []string
	var stateMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		states = append(states, r.Header.Get("X-State-ID"))
		switch len(states) {
		case 1:
			w.Header().Set("X-State-ID", "error-state")
			w.Header().Set("X-Request-ID", "error-request")
			w.WriteHeader(422)
			fmt.Fprint(w, `{"detail":{"reason":"source not supported"}}`)
		case 2:
			w.WriteHeader(503)
			fmt.Fprint(w, "remote unavailable")
		case 3:
			w.Header().Set("X-State-ID", "rotated-state")
			writeSensor(w)
		default:
			writeSensor(w)
		}
	}))
	defer server.Close()
	client := clientFor(t, server)
	session := sessionFor(t, client)
	params := nullgate.SensorParams{Protection: sensor, Script: "source"}
	_, err := session.Solve(context.Background(), params)
	var apiError *nullgate.APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != 422 || apiError.RequestID != "error-request" || !reflect.DeepEqual(apiError.Detail, map[string]any{"reason": "source not supported"}) {
		t.Fatalf("structured API error lost status/detail/request ID: %v", err)
	}
	_, err = session.Solve(context.Background(), params)
	if !errors.As(err, &apiError) || apiError.StatusCode != 503 || apiError.Detail != "remote unavailable" {
		t.Fatal("non-JSON API error lost its original detail")
	}
	for range 2 {
		if _, err := session.Solve(context.Background(), params); err != nil {
			t.Fatal(err)
		}
	}
	other := sessionFor(t, client)
	if _, err := other.Solve(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	if want := []string{"", "error-state", "error-state", "rotated-state", ""}; !reflect.DeepEqual(states, want) {
		t.Errorf("state stream = %q, want %q", states, want)
	}
}

func TestSessionCancellationWhileQueuedAndParallelSessionIndependence(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "blocked-session" {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		writeSensor(w)
	}))
	defer server.Close()
	defer close(release)
	client := clientFor(t, server)
	blocked, err := client.Open(nullgate.SessionOptions{Identity: identity, UserAgent: "blocked-session"})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	params := nullgate.SensorParams{Protection: sensor, Script: "source"}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() { _, err := blocked.Solve(firstCtx, params); firstDone <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached the service")
	}
	queuedCtx, cancelQueued := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelQueued()
	queuedDone := make(chan error, 1)
	go func() { _, err := blocked.Solve(queuedCtx, params); queuedDone <- err }()
	select {
	case err := <-queuedDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued cancellation was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued solve ignored its context while another request held the session")
	}
	other := sessionFor(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := other.Solve(ctx, params); err != nil {
		t.Fatalf("independent session was blocked by another session: %v", err)
	}
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Errorf("in-flight cancellation was lost: %v", err)
	}
}

func TestClosedClientAndSessionCannotContinue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("closed stream performed network I/O")
		writeSensor(w)
	}))
	defer server.Close()
	client := clientFor(t, server)
	session := sessionFor(t, client)
	session.Close()
	if _, err := session.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"}); !errors.Is(err, nullgate.ErrClosed) {
		t.Errorf("closed session: %v", err)
	}
	other := sessionFor(t, client)
	client.Close()
	if _, err := other.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"}); !errors.Is(err, nullgate.ErrClosed) {
		t.Errorf("client close did not close its streams: %v", err)
	}
	if _, err := client.Open(nullgate.SessionOptions{Identity: identity, UserAgent: "agent"}); !errors.Is(err, nullgate.ErrClosed) {
		t.Errorf("closed client opened a new stream: %v", err)
	}
}
