package pingone_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/pingone"
)

func TestProtectFetchAndSourceRecovery(t *testing.T) {
	var calls, sends int
	script := strings.Repeat("script", 400)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer gz.Close()
			reader = gz
		} else if r.URL.Path == "/pingone/prepare" {
			t.Error("large prepare request was not gzip encoded")
		}
		var body map[string]any
		if err := json.NewDecoder(reader).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/pingone/prepare" {
			for _, field := range []string{"client_token", "token_response", "jwt_device_attributes", "jwt_agent_payload", "behavioral"} {
				if _, ok := body[field]; ok {
					http.Error(w, "unexpected prepare field", http.StatusUnprocessableEntity)
					return
				}
			}
			if body["script"] != script {
				t.Error("prepare omitted source")
			}
			fmt.Fprint(w, `{"session":"prepared","request":{"role":"pingone.token","method":"GET","url":"https://identity.example/token.css","headers":{"Accept":"text/css"},"body":null,"credentials":"include"}}`)
			return
		}
		calls++
		if body["token_response"] != "css-token" || body["jwt_device_attributes"] != "device.jwt" || body["jwt_agent_payload"] != "agent.jwt" || body["behavioral"] != "behavior" {
			t.Error("protect lost token or JWT")
		}
		if calls == 1 {
			if _, ok := body["script"]; ok {
				t.Error("initial protect repeated source")
			}
			w.WriteHeader(428)
			fmt.Fprint(w, `{"code":"script_required","message":"source required","request_id":"retry"}`)
			return
		}
		if body["script"] != script {
			t.Error("retry omitted source")
		}
		fmt.Fprint(w, `{"data":"encoded","sdk_version":"1","device_id":"device","session":"next","request_id":"request"}`)
	}))
	defer server.Close()
	client, err := nullgate.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	visit, err := browser.New(browser.Options{UserAgent: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := visit.Page("https://identity.example/login", "<html></html>", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.PingOne.Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), contextKey{}, "value")
	result, err := session.Protect(ctx, page, pingone.Options{Script: script, JWTDeviceAttributes: "device.jwt", JWTAgentPayload: "agent.jwt", Behavioral: "behavior", Send: func(r *http.Request) (*http.Response, error) {
		sends++
		if r.Context().Value(contextKey{}) != "value" || r.Header.Get("Authorization") != "" || r.URL.Host != "identity.example" {
			t.Error("invalid target request context or credentials")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("css-token"))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Data != "encoded" || calls != 2 || sends != 1 {
		t.Fatalf("unexpected result or request counts: %#v %d %d", result, calls, sends)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "encoded") {
		t.Fatal("result leaks data")
	}
}

type contextKey struct{}

type trackedBody struct {
	io.Reader
	closed bool
	read   bool
}

func (b *trackedBody) Read(p []byte) (int, error) { b.read = true; return b.Reader.Read(p) }

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestProtectTargetFailureAndTokenShortcut(t *testing.T) {
	for _, tc := range []struct {
		name        string
		token       string
		status      int
		wantProtect bool
		sendError   bool
	}{
		{"target fails", "", 403, false, false},
		{"callback error", "", 200, false, true},
		{"supplied token", "supplied", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protect := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/pingone/prepare" {
					fmt.Fprint(w, `{"session":"prepared","request":{"role":"pingone.token","method":"GET","url":"https://identity.example/token.css","headers":{},"body":null,"credentials":"include"}}`)
					return
				}
				protect++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["client_token"] != tc.token {
					t.Error("token changed")
				}
				fmt.Fprint(w, `{"data":"encoded","sdk_version":"1","device_id":"device","session":"next","request_id":"request"}`)
			}))
			defer server.Close()
			client, err := nullgate.New("ng_test", api.Options{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			visit, err := browser.New(browser.Options{UserAgent: "test"})
			if err != nil {
				t.Fatal(err)
			}
			page, err := visit.Page("https://identity.example", "<html></html>", browser.PageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.PingOne.Session(visit)
			if err != nil {
				t.Fatal(err)
			}
			body := &trackedBody{Reader: strings.NewReader("failure")}
			sends := 0
			_, err = session.Protect(context.Background(), page, pingone.Options{Script: "source", ClientToken: tc.token, Send: func(*http.Request) (*http.Response, error) {
				sends++
				if tc.sendError {
					return &http.Response{StatusCode: tc.status, Body: body}, errors.New("target failed")
				}
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			}})
			if tc.wantProtect && (err != nil || protect != 1 || sends != 0) {
				t.Fatalf("shortcut: %v protect=%d sends=%d", err, protect, sends)
			}
			if !tc.wantProtect && (err == nil || protect != 0 || sends != 1 || !body.closed || body.read) {
				t.Fatalf("failure: %v protect=%d sends=%d closed=%v read=%v", err, protect, sends, body.closed, body.read)
			}
		})
	}
}

func TestProtectPreservesContinuationAcrossNavigationAndSourceChange(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		calls++
		if calls > 1 && body["session"] != "tab-device" {
			t.Error("navigation or source change lost continuation")
		}
		if calls > 1 && body["script"] == nil {
			t.Error("changed page or source omitted script")
		}
		fmt.Fprint(w, `{"data":"encoded","sdk_version":"1","device_id":"device","session":"tab-device","request_id":"request"}`)
	}))
	defer server.Close()
	client, err := nullgate.New("ng_test", api.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	visit, err := browser.New(browser.Options{UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := visit.Page("https://identity.example/login", "first", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := visit.Page("https://identity.example/next", "second", browser.PageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.PingOne.Session(visit)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		page   *browser.Page
		script string
	}{{first, "source"}, {second, "source"}, {second, "new source"}} {
		result, err := session.Protect(context.Background(), step.page, pingone.Options{Script: step.script, ClientToken: "token"})
		if err != nil || result.DeviceID != "device" {
			t.Fatalf("continuation: result=%v err=%v", result, err)
		}
	}
}

func TestProtectRejectsCredentialsInTargetRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		url     string
		headers map[string]string
	}{
		{"url", "https://identity.example/ng%5ftest", nil},
		{"header name", "https://identity.example/token", map[string]string{"ng_test": "value"}},
		{"header value", "https://identity.example/token", map[string]string{"X-Token": "Bearer ng_test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"session": "prepared",
					"request": map[string]any{"role": "pingone.token", "method": "GET", "url": tc.url, "headers": tc.headers, "body": nil, "credentials": "include"},
				})
			}))
			defer server.Close()
			client, err := nullgate.New("ng_test", api.Options{BaseURL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			visit, err := browser.New(browser.Options{UserAgent: "test"})
			if err != nil {
				t.Fatal(err)
			}
			page, err := visit.Page("https://identity.example", "html", browser.PageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.PingOne.Session(visit)
			if err != nil {
				t.Fatal(err)
			}
			sent := false
			_, err = session.Protect(context.Background(), page, pingone.Options{Script: "source", Send: func(*http.Request) (*http.Response, error) {
				sent = true
				return nil, nil
			}})
			if err == nil || sent || strings.Contains(err.Error(), "ng_test") {
				t.Fatalf("credential rejection: err=%v sent=%v", err, sent)
			}
		})
	}
}
