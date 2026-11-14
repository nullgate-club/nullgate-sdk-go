package nullgate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	ng "github.com/nullgate-club/nullgate-sdk-go/v2"
)

const profileID = "0123456789abcdef0123456789abcdef"

func TestProfileLifecycleAndSessionRotation(t *testing.T) {
	starts := make(chan map[string]any, 2)
	failure := make(chan error, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			failure <- err
			return
		}
		defer c.Close()
		var start map[string]any
		if err = c.ReadJSON(&start); err != nil {
			failure <- err
			return
		}
		starts <- start
		send := func(v any) bool {
			if e := c.WriteJSON(v); e != nil {
				failure <- e
				return false
			}
			return true
		}
		if !send(map[string]any{"type": "hello", "session": "next-session", "request_id": profileID}) {
			return
		}
		if !send(map[string]any{"type": "http", "id": 1, "request": map[string]any{"role": "script", "url": "https://target.test/a", "method": "GET", "headers": map[string]string{}, "body": nil, "credentials": "include"}}) {
			return
		}
		var reply map[string]any
		if err = c.ReadJSON(&reply); err != nil {
			failure <- err
			return
		}
		if reply["type"] != "http.result" {
			failure <- errors.New("missing HTTP result")
			return
		}
		if !send(map[string]any{"type": "http", "id": 2, "request": map[string]any{"role": "beacon", "url": "https://target.test/b", "method": "POST", "headers": map[string]string{}, "body": "", "credentials": "omit"}}) {
			return
		}
		if err = c.ReadJSON(&reply); err != nil {
			failure <- err
			return
		}
		if reply["type"] != "http.result" {
			failure <- errors.New("missing omit HTTP result")
			return
		}
		if !send(map[string]any{"type": "ready", "request_id": profileID}) {
			return
		}
		if !send(map[string]any{"type": "collected", "request_id": profileID}) {
			return
		}
		if err = c.ReadJSON(&reply); err != nil {
			return
		}
		if reply["type"] == "pagehide" {
			send(map[string]any{"type": "pagehide.done"})
			_ = c.ReadJSON(&reply)
		}
	}))
	defer server.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(ng.SessionOptions{UserAgent: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Page("https://target.test/", "<html></html>", ng.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan ng.CredentialsMode, 4)
	opts := ng.ThreatMetrixOptions{Collector: &ng.Collector{URL: "https://target.test/fp", OrgID: "org", SessionID: "sid"}, Send: func(_ context.Context, r ng.TargetRequest) (ng.TargetResponse, error) {
		seen <- r.Credentials
		return ng.TargetResponse{Status: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := page.ThreatMetrix(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	first := <-starts
	if first["session"] != nil || first["website"] != nil {
		t.Fatalf("invalid first start: %v", first)
	}
	if got := <-seen; got != ng.CredentialsInclude {
		t.Fatalf("credentials: %q", got)
	}
	if got := <-seen; got != ng.CredentialsOmit {
		t.Fatalf("credentials: %q", got)
	}
	if err = p.WaitCollected(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
		t.Fatal("collection closed profile")
	default:
	}
	if err = p.Pagehide(ctx, nil, false); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = page.ThreatMetrix(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	second := <-starts
	if second["session"] != "next-session" {
		b, _ := json.Marshal(second)
		t.Fatalf("session not rotated: %s", b)
	}
	_ = p.Close()
	select {
	case err := <-failure:
		t.Fatal(err)
	default:
	}
}

func TestProfileRejectsDuplicateOperation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		var v any
		_ = c.ReadJSON(&v)
		_ = c.WriteJSON(map[string]any{"type": "hello", "session": "s", "request_id": profileID})
		_ = c.WriteJSON(map[string]any{"type": "ready", "request_id": profileID})
		msg := map[string]any{"type": "http", "id": 1, "request": map[string]any{"role": "x", "url": "https://target.test/", "method": "GET", "headers": map[string]string{}, "body": nil, "credentials": "omit"}}
		_ = c.WriteJSON(msg)
		_ = c.WriteJSON(msg)
		for c.ReadJSON(&v) == nil {
		}
	}))
	defer server.Close()
	client, err := ng.NewClient("ng_test", ng.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s, err := client.Session(ng.SessionOptions{UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Page("https://target.test/", "", ng.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := page.ThreatMetrix(ctx, ng.ThreatMetrixOptions{Collector: &ng.Collector{URL: "https://target.test/", OrgID: "o", SessionID: "s"}, Send: func(ctx context.Context, r ng.TargetRequest) (ng.TargetResponse, error) {
		<-ctx.Done()
		return ng.TargetResponse{}, ctx.Err()
	}})
	if err != nil {
		var failure *ng.Error
		if !errors.As(err, &failure) || failure.Code != "protocol_error" {
			t.Fatal(err)
		}
		return
	}
	<-p.Done()
	var failure *ng.Error
	if !errors.As(p.Err(), &failure) || failure.Code != "protocol_error" {
		t.Fatalf("expected protocol error, got %v", p.Err())
	}
}
