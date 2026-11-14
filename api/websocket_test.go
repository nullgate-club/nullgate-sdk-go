package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
)

// An API HTTP/2 connection must not make a later WebSocket negotiate unsupported h2.
func TestWebSocketUsesHTTP1AfterHTTP2Request(t *testing.T) {
	var wasHTTP2 atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/account" {
			wasHTTP2.Store(r.ProtoMajor == 2)
			io.WriteString(w, `{"active":true}`)
			return
		}
		if r.ProtoMajor != 1 {
			t.Error("WebSocket did not use HTTP/1.1")
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("ready"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	supplied := server.Client()
	connection, err := api.New("ng_test", api.Options{BaseURL: server.URL, HTTPClient: supplied})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var account map[string]any
	if err = connection.Call(ctx, "/account", nil, &account, "", true); err != nil {
		t.Fatal(err)
	}
	if !wasHTTP2.Load() {
		t.Fatal("test setup did not establish HTTP/2")
	}
	conn, err := connection.OpenWebSocket(ctx, "/threatmetrix/profile")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kind, data, err := conn.ReadMessage()
	if err != nil || kind != websocket.TextMessage || string(data) != "ready" {
		t.Fatalf("WebSocket could not receive source message: %d %q %v", kind, data, err)
	}
	if !slices.Contains(supplied.Transport.(*http.Transport).TLSClientConfig.NextProtos, "h2") {
		t.Fatal("WebSocket modified caller TLS settings")
	}
}
