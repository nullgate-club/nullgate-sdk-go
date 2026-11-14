package nullgate_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	ng "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func TestProfileDoesNotBypassFailedTURNProxy(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	contacted := make(chan struct{})
	go func() {
		c, e := proxy.Accept()
		if e == nil {
			close(contacted)
			c.Close()
		}
	}()
	observed := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		var value map[string]any
		if c.ReadJSON(&value) != nil {
			return
		}
		_ = c.WriteJSON(map[string]any{"type": "hello", "session": "s", "request_id": profileID})
		_ = c.WriteJSON(map[string]any{"type": "ice", "id": 1, "server": map[string]any{"host": "127.0.0.1", "port": 9, "transport": "tcp", "username": "u", "credential": "p"}})
		if c.ReadJSON(&value) != nil {
			return
		}
		observed <- value["type"] == "ice.result" && value["observation"] == nil
		_ = c.WriteJSON(map[string]any{"type": "ice.release", "id": 1})
		_ = c.WriteJSON(map[string]any{"type": "ready", "request_id": profileID})
		for c.ReadJSON(&value) == nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := page.ThreatMetrix(ctx, ng.ThreatMetrixOptions{Collector: &ng.Collector{URL: "https://target.test/", OrgID: "o", SessionID: "s"}, Proxy: "http://" + proxy.Addr().String(), Send: func(context.Context, ng.TargetRequest) (ng.TargetResponse, error) { return ng.TargetResponse{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	select {
	case <-contacted:
	case <-ctx.Done():
		t.Fatal("TURN proxy was not contacted")
	}
	select {
	case ok := <-observed:
		if !ok {
			t.Fatal("failed allocation was not reported")
		}
	case <-ctx.Done():
		t.Fatal("missing TURN result")
	}
}
