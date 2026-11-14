package threatmetrix_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/threatmetrix"
)

func TestStartupGateHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var message any
		if conn.ReadJSON(&message) != nil {
			return
		}
		close(started)
		for conn.ReadJSON(&message) == nil {
		}
	}))
	defer server.Close()
	connection, err := api.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	visit, err := browser.New(browser.Options{UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := visit.Page("https://target.test/", "", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client := threatmetrix.New(connection)
	defer client.Close()
	session, err := client.Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	opts := threatmetrix.Options{Collector: &threatmetrix.Collector{URL: "https://target.test/", OrgID: "o", SessionID: "s"}, Send: func(context.Context, threatmetrix.TargetRequest) (threatmetrix.TargetResponse, error) {
		return threatmetrix.TargetResponse{}, nil
	}}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() { _, err := session.Start(firstCtx, page, opts); firstDone <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first startup did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = session.Start(ctx, page, opts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	cancelFirst()
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first startup did not stop")
	}
}
