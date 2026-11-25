package solver_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2/solver"
)

func newClient(t *testing.T, options solver.Options) *solver.Client {
	t.Helper()
	client, err := solver.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// A missing target setting must not silently produce a result for another visit.
func TestSolvePreservesVisitAndResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var visit struct {
			UserAgent string `json:"user_agent"`
			Proxy     string `json:"proxy"`
			Session   string `json:"session"`
			Transport struct {
				Emulation string         `json:"emulation"`
				TLS       map[string]any `json:"tls_options"`
				HTTP2     map[string]any `json:"http2_options"`
				Order     []string       `json:"headers_order"`
			} `json:"transport"`
		}
		if json.NewDecoder(r.Body).Decode(&visit) != nil || visit.UserAgent != "browser" || visit.Proxy != "http://proxy:8080" || visit.Session != "visit" || visit.Transport.Emulation != "Chrome154" || visit.Transport.TLS["min_tls_version"] != "TLS_1_2" || visit.Transport.HTTP2["initial_window_size"] != float64(65535) || len(visit.Transport.Order) != 2 || visit.Transport.Order[1] != "accept" {
			http.Error(w, "missing visit settings", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cookies":[{"name":"token","value":"v","domain":"example.com","path":"/","secure":true,"http_only":true,"expires":1700000000,"host_only":true,"same_site":"Lax"}],"result":{"status":"PASS","url":"https://example.com/","status_code":200}}`))
	}))
	defer server.Close()
	client := newClient(t, solver.Options{BaseURL: server.URL, HTTPClient: server.Client()})
	got, err := client.Solve(context.Background(), solver.Request{
		Type: solver.AmazonACIC, URL: "https://example.com/", UserAgent: "browser", Proxy: "http://proxy:8080", Session: "visit",
		Transport: &solver.Transport{Emulation: "Chrome154", TLSOptions: map[string]any{"min_tls_version": "TLS_1_2"}, HTTP2Options: map[string]any{"initial_window_size": 65535}, HeadersOrder: []string{"user-agent", "accept"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Cookies) != 1 || got.Cookies[0].Name != "token" || !got.Cookies[0].HTTPOnly || !got.Cookies[0].Secure || got.Cookies[0].HostOnly == nil || !*got.Cookies[0].HostOnly || got.Cookies[0].SameSite != "Lax" || got.Cookies[0].Expires == nil || *got.Cookies[0].Expires != 1700000000 || got.Cookies[0].Path != "/" || got.Cookies[0].Domain != "example.com" {
		t.Fatalf("cookie attributes lost: %+v", got.Cookies)
	}
	if got.Result.Status != "PASS" || got.Result.StatusCode != 200 || got.Result.URL != "https://example.com/" {
		t.Fatalf("product result lost: %+v", got.Result)
	}
}

// A failed solve must retain the server's diagnostics and HTTP status.
func TestSolveStructuredError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"code":"target_error","message":"target failed","stage":"submit","request_id":"request-1","cause":"rejected"}`))
	}))
	defer server.Close()
	_, err := newClient(t, solver.Options{BaseURL: server.URL}).Solve(context.Background(), solver.Request{})
	var apiError *solver.Error
	if !errors.As(err, &apiError) || apiError.Code != "target_error" || apiError.Stage != "submit" || apiError.RequestID != "request-1" || apiError.Cause != "rejected" || apiError.Status != http.StatusBadGateway {
		t.Fatalf("structured error lost: %v", err)
	}
}

// A truncated or wrong-shaped success must not be reported as a completed solve.
func TestSolveRejectsMalformedSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"cookies":[],"result":null}`, `{"cookies":[],"result":[]}`, `{"cookies":null,"result":{}}`, `{"cookies":[],"result":{} } trailing`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			_, err := newClient(t, solver.Options{BaseURL: server.URL}).Solve(context.Background(), solver.Request{})
			var apiError *solver.Error
			if !errors.As(err, &apiError) || apiError.Code != "invalid_response" {
				t.Fatalf("expected malformed response, got %v", err)
			}
		})
	}
}

// A caller deadline must remain recognizable through the SDK error.
func TestSolveDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := newClient(t, solver.Options{BaseURL: server.URL}).Solve(ctx, solver.Request{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}
