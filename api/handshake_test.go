package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
)

// A long maintenance delay must remain cancellable, not become an immediate rejection.
func TestWebSocketMaintenanceWaitHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(503)
		io.WriteString(w, `{"code":"maintenance","message":"draining","request_id":"request-1"}`)
	}))
	defer server.Close()
	connection, err := api.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = connection.OpenWebSocket(ctx, "/threatmetrix/profile")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("maintenance wait did not preserve cancellation: %v", err)
	}
}

// HTTP-date Retry-After remains valid for WebSocket handshakes, including a past date.
func TestWebSocketMaintenanceAcceptsHTTPDate(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", time.Unix(0, 0).UTC().Format(http.TimeFormat))
			w.WriteHeader(503)
			io.WriteString(w, `{"code":"maintenance","message":"draining","request_id":"request-1"}`)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("ready"))
	}))
	defer server.Close()
	connection, err := api.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := connection.OpenWebSocket(ctx, "/threatmetrix/profile")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, body, err := conn.ReadMessage()
	if err != nil || string(body) != "ready" {
		t.Fatalf("maintenance recovery did not establish the profile connection: %q %v", body, err)
	}
}

// Present-but-empty fields are malformed errors, not usable service rejections.
func TestWebSocketRejectsEmptyErrorEnvelopeFields(t *testing.T) {
	for _, body := range []string{`{"code":"","message":"reason","request_id":"r"}`, `{"code":"invalid_request","message":"","request_id":"r"}`, `{"code":"invalid_request","message":"reason","request_id":""}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400); io.WriteString(w, body) }))
			defer server.Close()
			connection, err := api.New("ng_test", api.Options{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_, err = connection.OpenWebSocket(context.Background(), "/threatmetrix/profile")
			var detail *api.Error
			if !errors.As(err, &detail) || detail.Code != "protocol_error" || detail.Status != 400 {
				t.Fatalf("malformed handshake rejection escaped validation: %v", err)
			}
		})
	}
}
