package nullgate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestHTTPErrorMetadataCompatibility(t *testing.T) {
	for _, metadata := range []string{"", `,"error":{"code":"FUTURE_ERROR","origin":"upstream","message":"safe","retryable":null}`, `,"error":{"code":123}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Nullgate-Error-Format") != "1" {
				t.Error("missing negotiation")
			}
			w.Header().Set("X-Request-ID", "diagnostic")
			w.WriteHeader(502)
			fmt.Fprint(w, `{"detail":"private-body"`+metadata+`}`)
		}))
		client := clientFor(t, server)
		_, err := sessionFor(t, client).Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"})
		var failure *nullgate.APIError
		if !errors.As(err, &failure) || failure.StatusCode != 502 || failure.Detail != "private-body" {
			t.Fatalf("lost legacy service error: %v", err)
		}
		if strings.Contains(metadata, "FUTURE_ERROR") {
			if failure.ErrorInfo == nil || failure.ErrorInfo.Code != "FUTURE_ERROR" {
				t.Fatal("lost future code")
			}
			if !strings.HasPrefix(err.Error(), "nullgate: FUTURE_ERROR origin=upstream") {
				t.Fatal("structured code did not lead the HTTP error message")
			}
		} else if failure.ErrorInfo != nil {
			t.Fatal("invented metadata for legacy/malformed 502")
		}
		if strings.Contains(fmt.Sprintf("%v %#v", err, err), "private-body") {
			t.Fatal("private detail leaked")
		}
		server.Close()
	}
}

func TestProfileErrorNegotiationAndTargetStatus(t *testing.T) {
	for _, negotiated := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			t.Run(fmt.Sprintf("negotiated=%v/failed=%v", negotiated, failed), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-Nullgate-Error-Format") != "1" {
						t.Error("missing WS negotiation")
					}
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
					hello := map[string]any{"type": "hello", "state_id": "continued", "request_id": profileRequestID}
					if negotiated {
						hello["error_format"] = 1
					}
					conn.WriteJSON(hello)
					conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"http","id":1,"request":{"role":"tags","url":"https://target.example/private?secret=1","method":"GET","headers":{},"body":null,"credentials":"include"}}`))
					var reply map[string]json.RawMessage
					if err := conn.ReadJSON(&reply); err != nil {
						t.Error(err)
						return
					}
					wire, _ := json.Marshal(reply)
					if strings.Contains(string(wire), "private-local") {
						t.Error("local exception leaked")
					}
					var kind string
					json.Unmarshal(reply["type"], &kind)
					if failed {
						if kind != "http.error" {
							t.Errorf("wrong callback type: %s", kind)
						}
						if negotiated {
							var cause nullgate.TransportCause
							if json.Unmarshal(reply["error"], &cause) != nil || cause.Kind != "unknown" {
								t.Error("unknown exception was guessed")
							}
						} else if len(reply) != 3 {
							t.Error("legacy callback key set changed")
						}
					} else if kind != "http.result" {
						t.Error("real target502 became transport failure")
					}
					if !failed {
						var response struct {
							Status int `json:"status"`
						}
						if json.Unmarshal(reply["response"], &response) != nil || response.Status != 502 {
							t.Error("real target status changed")
						}
					}
					message := map[string]any{"type": "error", "status": 502, "detail": "private-detail", "request_id": profileRequestID}
					if negotiated && failed {
						message["error"] = map[string]any{"code": "CLIENT_TRANSPORT_ERROR", "origin": "client", "message": "Target request failed", "retryable": nil, "stage": "target_http", "command_id": 1, "target": map[string]string{"role": "tags", "method": "GET", "host": "target.example"}, "cause": map[string]string{"kind": "unknown"}}
					}
					conn.WriteJSON(message)
					conn.ReadMessage()
				}))
				defer server.Close()
				client, err := nullgate.NewClient(apiKey, nullgate.Options{ProfileBaseURL: server.URL})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				original := errors.New("private-local credentials")
				target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
					if failed {
						return nullgate.TargetResponse{}, original
					}
					return nullgate.TargetResponse{Status: 502}, nil
				})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err = sessionFor(t, client).Profile(ctx, profileParams(), target)
				var failure *nullgate.APIError
				if !errors.As(err, &failure) || failure.StatusCode != 502 {
					t.Fatalf("lost service failure: %v", err)
				}
				if (negotiated && failed) != errors.Is(err, original) {
					t.Fatal("local target cause lost or invented")
				}
				if negotiated && failed && (failure.ErrorInfo == nil || failure.ErrorInfo.Target.Host != "target.example") {
					t.Fatal("lost target context")
				}
				if negotiated && failed && !strings.HasPrefix(err.Error(), "nullgate: CLIENT_TRANSPORT_ERROR origin=client") {
					t.Fatal("structured cause did not lead the default message")
				}
				if strings.Contains(fmt.Sprintf("%v %#v", err, err), "private-") {
					t.Fatal("private data leaked")
				}
			})
		}
	}
}

func TestProfileTargetCauseRequiresMatchingCommand(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        string
		origin      string
		commandID   any
		secondFails bool
		want        string
	}{
		{"first", "CLIENT_TRANSPORT_ERROR", "client", 1, true, "first"},
		{"second", "CLIENT_TRANSPORT_ERROR", "client", 2, true, "second"},
		{"real target 502", "CLIENT_TRANSPORT_ERROR", "client", 2, false, ""},
		{"unrelated origin", "CLIENT_TRANSPORT_ERROR", "service", 1, true, ""},
		{"unrelated code", "UPSTREAM_ERROR", "client", 1, true, ""},
		{"missing id", "CLIENT_TRANSPORT_ERROR", "client", nil, true, ""},
		{"unknown id", "CLIENT_TRANSPORT_ERROR", "client", 3, true, ""},
		{"invalid id", "CLIENT_TRANSPORT_ERROR", "client", 0, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				conn.WriteJSON(map[string]any{"type": "hello", "state_id": "continued", "request_id": profileRequestID, "error_format": 1})
				for id := 1; id <= 2; id++ {
					conn.WriteJSON(map[string]any{"type": "http", "id": id, "request": map[string]any{
						"role": "tags", "url": fmt.Sprintf("https://target.example/%d", id), "method": "GET", "headers": map[string]string{}, "body": nil, "credentials": "include",
					}})
				}
				for range 2 {
					var reply map[string]any
					if err := conn.ReadJSON(&reply); err != nil {
						t.Error(err)
						return
					}
					if reply["id"] == float64(2) && !tc.secondFails {
						if reply["type"] != "http.result" || reply["response"].(map[string]any)["status"] != float64(502) {
							t.Error("real target 502 changed")
						}
					}
				}
				info := map[string]any{"code": tc.code, "origin": tc.origin, "message": "safe", "retryable": nil}
				if tc.commandID != nil {
					info["command_id"] = tc.commandID
				}
				conn.WriteJSON(map[string]any{"type": "error", "status": 502, "detail": "safe", "request_id": profileRequestID, "error": info})
				conn.ReadMessage()
			}))
			defer server.Close()
			client, err := nullgate.NewClient(apiKey, nullgate.Options{ProfileBaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			first, second := errors.New("first private failure"), errors.New("second private failure")
			target := profileTarget(t, func(_ context.Context, request nullgate.TargetRequest) (nullgate.TargetResponse, error) {
				if strings.HasSuffix(request.URL, "/1") {
					return nullgate.TargetResponse{}, first
				}
				if tc.secondFails {
					return nullgate.TargetResponse{}, second
				}
				return nullgate.TargetResponse{Status: 502}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = sessionFor(t, client).Profile(ctx, profileParams(), target)
			var failure *nullgate.APIError
			if !errors.As(err, &failure) {
				t.Fatalf("lost service failure: %v", err)
			}
			if errors.Is(err, first) != (tc.want == "first") || errors.Is(err, second) != (tc.want == "second") {
				t.Fatal("attached unrelated local target failure")
			}
		})
	}
}
