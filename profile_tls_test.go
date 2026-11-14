package nullgate_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	ng "github.com/nullgate-club/nullgate-sdk-go/v2"
)

// A warmed HTTP/2 API connection must not make WebSocket negotiate unsupported h2.
func TestProfileUsesHTTP1AfterHTTP2AccountRequest(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/account" {
			io.WriteString(w, accountJSON)
			return
		}
		if r.ProtoMajor != 1 {
			t.Error("profile did not request HTTP/1.1")
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		var frame map[string]any
		if err = conn.ReadJSON(&frame); err != nil {
			return
		}
		id := "0123456789abcdef0123456789abcdef"
		for _, frame := range []map[string]any{{"type": "hello", "session": "continued", "request_id": id}, {"type": "ready", "request_id": id}, {"type": "collected", "request_id": id}} {
			if err = conn.WriteJSON(frame); err != nil {
				return
			}
		}
		for conn.ReadJSON(&frame) == nil {
			if frame["type"] == "pagehide" {
				_ = conn.WriteJSON(map[string]string{"type": "pagehide.done"})
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	supplied := server.Client()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: server.URL, HTTPClient: supplied})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = client.Account(ctx); err != nil {
		t.Fatal(err)
	}
	session, err := client.Session(ng.SessionOptions{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Page("https://target.test/", "<html></html>", ng.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := page.ThreatMetrix(ctx, ng.ThreatMetrixOptions{ScriptURL: "/tags.js", Send: func(context.Context, ng.TargetRequest) (ng.TargetResponse, error) {
		return ng.TargetResponse{}, errors.New("unexpected target request")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	if err = profile.WaitCollected(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(supplied.Transport.(*http.Transport).TLSClientConfig.NextProtos, "h2") {
		t.Fatal("profile modified caller TLS configuration")
	}
}
