package nullgate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/v2"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/threatmetrix"
)

// Closing the assembled client must not leave another product's request or profile running.
func TestCloseCancelsAccountRequestAndProfile(t *testing.T) {
	accountStarted := make(chan struct{})
	targetStarted := make(chan struct{})
	targetStopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/account" {
			close(accountStarted)
			<-r.Context().Done()
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		var frame map[string]any
		if conn.ReadJSON(&frame) != nil {
			return
		}
		id := "0123456789abcdef0123456789abcdef"
		for _, frame := range []map[string]any{
			{"type": "hello", "session": "session-1", "request_id": id},
			{"type": "ready", "request_id": id},
			{"type": "http", "id": 1, "request": map[string]any{"role": "collector", "url": "https://target.test/fp", "method": "GET", "headers": map[string]string{}, "body": nil, "credentials": "omit"}},
		} {
			if conn.WriteJSON(frame) != nil {
				return
			}
		}
		for conn.ReadJSON(&frame) == nil {
			if frame["type"] == "pagehide" {
				_ = conn.WriteJSON(map[string]string{"type": "pagehide.done"})
			}
		}
	}))
	defer server.Close()
	client, err := nullgate.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	visit, err := browser.New(browser.Options{UserAgent: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := visit.Page("https://target.test/", "<html></html>", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.ThreatMetrix.Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	profile, err := session.Start(ctx, page, threatmetrix.Options{ScriptURL: "/tags.js", Send: func(ctx context.Context, _ threatmetrix.TargetRequest) (threatmetrix.TargetResponse, error) {
		close(targetStarted)
		<-ctx.Done()
		close(targetStopped)
		return threatmetrix.TargetResponse{}, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() { _, err := client.Accounts.Get(ctx); requestDone <- err }()
	for _, started := range []<-chan struct{}{accountStarted, targetStarted} {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("product work did not start")
		}
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("API request lost cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("API request survived root close")
	}
	select {
	case <-profile.Done():
	case <-ctx.Done():
		t.Fatal("profile survived root close")
	}
	select {
	case <-targetStopped:
	case <-ctx.Done():
		t.Fatal("target callback survived root close")
	}
}
