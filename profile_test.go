package nullgate_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

const profileRequestID = "83d0dcf8-e826-4bf9-befe-feb97a9697ad"

func profileSession(t *testing.T, serve func(*websocket.Conn)) (*nullgate.Client, *nullgate.Session) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Error(err)
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"hello","state_id":"next-profile-state","request_id":"`+profileRequestID+`"}`)); err != nil {
			t.Error(err)
			return
		}
		serve(conn)
	}))
	t.Cleanup(server.Close)
	client, err := nullgate.NewClient(apiKey, nullgate.Options{ProfileBaseURL: server.URL, AnalyticsURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, sessionFor(t, client)
}

func profileParams() nullgate.ThreatMetrixParams {
	return nullgate.ThreatMetrixParams{Protection: nullgate.ThreatMetrix{
		Page: page, TagsURL: "https://arbitrary-profile.example/fp/tags.js?org_id=org&session_id=source-session",
	}}
}

func profileTarget(t *testing.T, fetch nullgate.TargetFetch) nullgate.Target {
	t.Helper()
	target, err := nullgate.NewTarget(fetch, "")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestProfileConcurrentBinaryHTTPAndExplicitDeparture(t *testing.T) {
	unblockSlow, collect := make(chan struct{}), make(chan struct{})
	_, session := profileSession(t, func(conn *websocket.Conn) {
		requests := []string{
			`{"type":"http","id":1,"request":{"role":"slow","url":"https://target.example/slow","method":"POST","headers":{},"body":"AP+A","credentials":"include"}}`,
			`{"type":"http","id":2,"request":{"role":"fast","url":"https://target.example/fast","method":"POST","headers":{},"body":"","credentials":"omit"}}`,
		}
		for _, request := range requests {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
				t.Error(err)
				return
			}
		}
		var result struct {
			ID       int `json:"id"`
			Response struct {
				Status int    `json:"status"`
				Body   string `json:"body"`
			} `json:"response"`
		}
		if err := conn.ReadJSON(&result); err != nil {
			t.Error(err)
			return
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(result.Response.Body)
		if err != nil || result.ID != 2 || result.Response.Status != 418 || !bytes.Equal(decoded, []byte{0, 255, 128}) {
			t.Error("blocked HTTP request stalled another request, or binary/error response facts changed")
		}
		close(unblockSlow)
		if err := conn.ReadJSON(&result); err != nil {
			t.Error(err)
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ready","request_id":"`+profileRequestID+`"}`)); err != nil {
			t.Error(err)
			return
		}
		select {
		case <-collect:
		case <-time.After(5 * time.Second):
			t.Error("collection was never requested")
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"collected","request_id":"`+profileRequestID+`"}`)); err != nil {
			t.Error(err)
			return
		}
		for index := range 2 {
			var departure struct {
				Type      string `json:"type"`
				AtMS      int64  `json:"at_ms"`
				Persisted bool   `json:"persisted"`
			}
			if err := conn.ReadJSON(&departure); err != nil {
				t.Error(err)
				return
			}
			if departure.Type != "pagehide" || departure.Persisted != (index == 0) || (index == 0 && departure.AtMS != 1234) {
				t.Error("collected closed the socket or explicit departure facts changed")
			}
			if index == 0 {
				if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"http","id":3,"request":{"role":"departure","url":"https://target.example/departure","method":"GET","headers":{},"body":null,"credentials":"omit"}}`)); err != nil {
					t.Error(err)
					return
				}
				if err := conn.ReadJSON(&result); err != nil || result.ID != 3 || result.Response.Status != 204 {
					t.Error("network work was not serviced while Pagehide awaited its acknowledgment")
					return
				}
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pagehide.done"}`)); err != nil {
				t.Error(err)
				return
			}
		}
		var final map[string]any
		if err := conn.ReadJSON(&final); err != nil || final["type"] != "close" {
			t.Error("Close did not terminate explicitly, or invented a pagehide")
		}
	})
	target := profileTarget(t, func(ctx context.Context, request nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		switch request.Role {
		case "slow":
			if !bytes.Equal(request.Body, []byte{0, 255, 128}) || request.Credentials != nullgate.CredentialsInclude {
				t.Error("request bytes or native include policy changed")
			}
			select {
			case <-unblockSlow:
			case <-ctx.Done():
				return nullgate.TargetResponse{}, ctx.Err()
			}
		case "fast":
			if request.Body == nil || len(request.Body) != 0 || request.Credentials != nullgate.CredentialsOmit {
				t.Error("present-empty body or native omit policy was lost")
			}
			return nullgate.TargetResponse{Status: 418, Body: []byte{0, 255, 128}}, nil
		case "departure":
			if request.Body != nil {
				t.Error("absent HTTP body became a present body")
			}
		}
		return nullgate.TargetResponse{Status: 204}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	profile, err := session.Profile(ctx, profileParams(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	waiting, stopWaiting := context.WithTimeout(ctx, 10*time.Millisecond)
	err = profile.WaitCollected(waiting)
	stopWaiting()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ready was treated as collected: %v", err)
	}
	close(collect)
	if err := profile.WaitCollected(ctx); err != nil {
		t.Fatal(err)
	}
	at := int64(1234)
	if err := profile.Pagehide(ctx, &at, true); err != nil {
		t.Fatal(err)
	}
	if err := profile.Pagehide(ctx, nil, false); err != nil {
		t.Fatal(err)
	}
}

func TestProfileOwnerCloseCancelsTargetWork(t *testing.T) {
	for _, owner := range []string{"profile", "session", "client", "context"} {
		t.Run(owner, func(t *testing.T) {
			started, canceled := make(chan struct{}), make(chan struct{})
			client, session := profileSession(t, func(conn *websocket.Conn) {
				conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ready","request_id":"`+profileRequestID+`"}`))
				conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"http","id":1,"request":{"role":"pending","url":"https://target.example/pending","method":"GET","headers":{},"body":null,"credentials":"omit"}}`))
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
				}
			})
			target := profileTarget(t, func(ctx context.Context, _ nullgate.TargetRequest) (nullgate.TargetResponse, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				return nullgate.TargetResponse{}, ctx.Err()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			profile, err := session.Profile(ctx, profileParams(), target)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("target request was never started")
			}
			switch owner {
			case "profile":
				profile.Close()
			case "session":
				session.Close()
			case "client":
				client.Close()
			case "context":
				cancel()
			}
			select {
			case <-profile.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("owner close did not join profile tasks")
			}
			select {
			case <-canceled:
			default:
				t.Fatal("profile finished without canceling its owned target request")
			}
		})
	}
}

func TestProfileRejectsMalformedAndDuplicateOperations(t *testing.T) {
	valid := `{"type":"http","id":1,"request":{"role":"tags","url":"https://target.example/tags","method":"GET","headers":{},"body":null,"credentials":"include"}}`
	for name, messages := range map[string][]string{
		"unknown kind":            {`{"type":"execute","source":"not executable"}`},
		"string ID":               {strings.Replace(valid, `"id":1`, `"id":"1"`, 1)},
		"duplicate ID":            {valid, valid},
		"invalid base64":          {strings.Replace(valid, `"body":null`, `"body":"YQ==\n"`, 1)},
		"unknown credential mode": {strings.Replace(valid, `"include"`, `"same-origin"`, 1)},
		"unknown release":         {`{"type":"ice.release","id":3}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, session := profileSession(t, func(conn *websocket.Conn) {
				for _, message := range messages {
					conn.WriteMessage(websocket.TextMessage, []byte(message))
				}
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
				}
			})
			target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
				return nullgate.TargetResponse{Status: 204}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			profile, err := session.Profile(ctx, profileParams(), target)
			var failure *nullgate.ProtocolError
			if profile != nil || !errors.As(err, &failure) || failure.RequestID != profileRequestID {
				t.Fatalf("malformed source work did not fail with its source request ID: %v", err)
			}
		})
	}
}

func TestProfileServiceFailureAndLocalProxyRedaction(t *testing.T) {
	_, session := profileSession(t, func(conn *websocket.Conn) {
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","status":422,"detail":"private source credential","request_id":"`+profileRequestID+`"}`))
		conn.ReadMessage()
	})
	target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		return nullgate.TargetResponse{}, errors.New("unused")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	profile, err := session.Profile(ctx, profileParams(), target)
	var failure *nullgate.APIError
	if profile != nil || !errors.As(err, &failure) || failure.StatusCode != 422 || failure.RequestID != profileRequestID {
		t.Fatalf("source failure became success or lost status/correlation: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", err), "private source credential") {
		t.Fatal("service detail leaked through default error rendering")
	}
	for _, address := range []string{"http://private-user:private-password@proxy.example:0", "ftp://private-user:private-password@proxy.example", "socks5://private-user:private-password@proxy.example/?query=1"} {
		_, err := nullgate.NewTarget(func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
			return nullgate.TargetResponse{}, nil
		}, address)
		if err == nil || strings.Contains(fmt.Sprintf("%#v", err), "private-") {
			t.Fatal("invalid target proxy was accepted or exposed credentials")
		}
	}
}

func TestProfileObservationPrivacyAndExplicitEmptyLists(t *testing.T) {
	starts := make(chan []byte, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, start, err := conn.ReadMessage()
		if err != nil {
			t.Error(err)
			return
		}
		starts <- start
		for _, message := range []string{
			`{"type":"hello","state_id":"observation-state","request_id":"` + profileRequestID + `"}`,
			`{"type":"ready","request_id":"` + profileRequestID + `"}`,
		} {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				t.Error(err)
				return
			}
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := nullgate.NewClient(apiKey, nullgate.Options{ProfileBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	session := sessionFor(t, client)
	target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		t.Error("observation startup unexpectedly requested target HTTP")
		return nullgate.TargetResponse{}, errors.New("unexpected target request")
	})
	const privateText = "private-observation@example.test"
	for _, name := range []string{"absent", "empty", "observed"} {
		t.Run(name, func(t *testing.T) {
			params := profileParams()
			switch name {
			case "empty":
				params.Inputs = []nullgate.Input{}
				params.Actions = []nullgate.Action{}
			case "observed":
				params.Inputs = []nullgate.Input{{"id": "email", "value": privateText}}
				params.Actions = []nullgate.Action{{
					"type": "input", "id": "email", "value": nullgate.PrepareInputs(params.Inputs)[0].Value,
				}}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			profile, err := session.Profile(ctx, params, target)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			start := <-starts
			if strings.Contains(string(start), privateText) {
				t.Fatal("raw observation text crossed the service boundary")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(start, &fields); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"inputs", "actions"} {
				value, present := fields[field]
				switch name {
				case "absent":
					if present {
						t.Errorf("absent %s changed stored observations: %s", field, value)
					}
				case "empty":
					if string(value) != "[]" {
						t.Errorf("explicit empty %s must clear observations, got %s", field, value)
					}
				case "observed":
					var observations []struct {
						Value struct {
							Length int `json:"length"`
						} `json:"value"`
					}
					if err := json.Unmarshal(value, &observations); err != nil {
						t.Fatalf("%s did not contain prepared values: %v", field, err)
					}
					if len(observations) != 1 || observations[0].Value.Length != len(privateText) {
						t.Errorf("%s did not retain the prepared observation", field)
					}
				}
			}
		})
	}
}

func TestProfileRejectsUnsafeActionsBeforeConnecting(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connections.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := nullgate.NewClient(apiKey, nullgate.Options{ProfileBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	session := sessionFor(t, client)
	target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		return nullgate.TargetResponse{}, errors.New("unexpected target request")
	})
	for name, action := range map[string]nullgate.Action{
		"raw input":    {"type": "input", "value": "private text"},
		"raw change":   {"type": "change", "value": "private text"},
		"invalid JSON": {"type": "mousemove", "x": func() {}},
	} {
		t.Run(name, func(t *testing.T) {
			params := profileParams()
			params.Actions = []nullgate.Action{action}
			profile, err := session.Profile(context.Background(), params, target)
			if err == nil || profile != nil || connections.Load() != 0 {
				t.Fatalf("unsafe actions reached profile service: profile=%v err=%v connections=%d",
					profile, err, connections.Load())
			}
		})
	}
}
