package nullgate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	ng "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func TestProfileCancellationStopsTargetWork(t *testing.T) {
	entered := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var v any
		if conn.ReadJSON(&v) != nil {
			return
		}
		_ = conn.WriteJSON(map[string]any{"type": "hello", "session": "s", "request_id": profileID})
		_ = conn.WriteJSON(map[string]any{"type": "ready", "request_id": profileID})
		_ = conn.WriteJSON(map[string]any{"type": "http", "id": 1, "request": map[string]any{"role": "script", "url": "https://target.test/", "method": "GET", "headers": map[string]string{}, "body": nil, "credentials": "omit"}})
		for conn.ReadJSON(&v) == nil {
		}
	}))
	defer server.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(ng.SessionOptions{UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Page("https://target.test/", "", ng.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := page.ThreatMetrix(ctx, ng.ThreatMetrixOptions{Collector: &ng.Collector{URL: "https://target.test/", OrgID: "o", SessionID: "s"}, Send: func(ctx context.Context, r ng.TargetRequest) (ng.TargetResponse, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return ng.TargetResponse{}, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("target did not start")
	}
	cancel()
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("profile did not stop")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("target work survived cancellation")
	}
	if !errors.Is(p.Err(), context.Canceled) {
		t.Fatalf("unexpected terminal error: %v", p.Err())
	}
}
