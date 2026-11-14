package nullgate_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ng "github.com/nullgate-club/nullgate-sdk-go/v2"
)

const accountJSON = `{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","balance":"1.234567","currency":"USD","created_at":"2026-11-01T00:00:00Z","active":true,"prices_per_1000":{"akamai.sensor":"2.500000"},"usage":[]}`

// A redirect must never forward an API key to a different server.
func TestAPIRedirectDoesNotLeakCredentials(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); io.WriteString(w, accountJSON) }))
	defer target.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer api.Close()
	provided := &http.Client{}
	client, err := ng.NewClient("ng_secret", ng.Options{BaseURL: api.URL, HTTPClient: provided})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Account(context.Background())
	var failure *ng.Error
	if !errors.As(err, &failure) || failure.Status != 307 || reached.Load() {
		t.Fatalf("redirect was not rejected: err=%v target=%v", err, reached.Load())
	}
	if provided.CheckRedirect != nil {
		t.Fatal("caller HTTP client was modified")
	}
}

// A server without gzip support must receive a safe replay and future uncompressed requests.
func TestGzipNegotiationPreservesSensorContinuation(t *testing.T) {
	requests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if r.Header.Get("Content-Encoding") != "gzip" {
				t.Error("first large request was not gzipped")
			}
			reader, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, reader)
			reader.Close()
			w.WriteHeader(415)
			io.WriteString(w, `{"code":"invalid_request","message":"unsupported encoding","request_id":"e"}`)
			return
		}
		if r.Header.Get("Content-Encoding") != "" {
			t.Error("gzip was not disabled")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if requests == 3 && (body["session"] != "continued" || body["script_digest"] == nil || body["script"] != nil) {
			t.Error("continuation lost during compression negotiation")
		}
		io.WriteString(w, `{"session":"continued","script_retained":true,"request_id":"r","request":{"url":"https://target.test/sensor","body":"generated","headers":{},"send_at":0}}`)
	}))
	defer api.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(ng.SessionOptions{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Page("https://target.test/", "<html>"+strings.Repeat("x", 3000)+"</html>", ng.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		result, err := page.Sensor(context.Background(), ng.SensorOptions{Script: "source", ScriptURL: "/sensor"})
		if err != nil {
			t.Fatal(err)
		}
		if result.URL != "https://target.test/sensor" || result.Headers["origin"] != "https://target.test" {
			t.Fatal("target request context was lost")
		}
	}
	if requests != 3 {
		t.Fatalf("got %d requests, want one negotiation plus two generations", requests)
	}
}

// Only explicit maintenance denial may replay an ordinary API operation.
func TestMaintenanceAndMalformedAccount(t *testing.T) {
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			io.WriteString(w, `{"code":"maintenance","message":"draining","request_id":"r"}`)
			return
		}
		if calls == 2 {
			io.WriteString(w, accountJSON)
			return
		}
		io.WriteString(w, `{"id":"id","balance":1.234567}`)
	}))
	defer api.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	account, err := client.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if account.Balance != "1.234567" || account.PricesPer1000["akamai.sensor"] != "2.500000" {
		t.Fatal("decimal amounts were not preserved")
	}
	_, err = client.Account(context.Background())
	var failure *ng.Error
	if !errors.As(err, &failure) || failure.Code != "protocol_error" || calls != 3 {
		t.Fatalf("malformed account was accepted or replayed: %v calls=%d", err, calls)
	}
}

// Cancellation must stop an API operation and remain visible to errors.Is.
func TestCanceledRequestPreservesContextCause(t *testing.T) {
	started := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer api.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Account(ctx); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost context cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request ignored cancellation")
	}
}

// Reporting is anonymous and non-2xx delivery is not a success or refund.
func TestReportDoesNotSendAPIKey(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analytics/report" || r.Header.Get("Authorization") != "" {
			t.Error("report used authentication or wrong route")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["request_id"] != "request-123" {
			t.Error("report request id was lost")
		}
		w.WriteHeader(503)
	}))
	defer api.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	delivered, err := client.Report(context.Background(), "request-123")
	if err != nil || delivered {
		t.Fatalf("report falsely succeeded: %v %v", delivered, err)
	}
}
