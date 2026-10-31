package nullgate_test

import (
	"context"
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

func TestNewThreatMetrixCollectorRejectsInvalidSources(t *testing.T) {
	for _, test := range []struct {
		name, address, orgID, sessionID string
	}{
		{"empty URL", "", "org", "session"},
		{"relative URL", "/collector.js", "org", "session"},
		{"unsupported scheme", "ftp://collector.example/script.js", "org", "session"},
		{"missing host", "https:///collector.js", "org", "session"},
		{"userinfo", "https://private-user:private-password@collector.example/script.js", "org", "session"},
		{"empty userinfo", "https://@collector.example/script.js", "org", "session"},
		{"fragment", "https://collector.example/script.js#fragment", "org", "session"},
		{"empty fragment", "https://collector.example/script.js#", "org", "session"},
		{"raw whitespace", "https://collector.example/script.js?opaque=private value", "org", "session"},
		{"backslash", "https://collector.example/path\\script.js", "org", "session"},
		{"nonnumeric port", "https://collector.example:private-port/script.js", "org", "session"},
		{"out of range port", "https://collector.example:65536/script.js", "org", "session"},
		{"zero port", "https://collector.example:0/script.js", "org", "session"},
		{"empty port", "https://collector.example:/script.js", "org", "session"},
		{"empty organization", directCollectorURL, "", "session"},
		{"empty session", directCollectorURL, "org", ""},
		{"whitespace organization", directCollectorURL, " \t", "session"},
		{"whitespace session", directCollectorURL, "org", "\u2003"},
		{"organization line break", directCollectorURL, "org\rprivate-org", "session"},
		{"session line break", directCollectorURL, "org", "session\nprivate-session"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := nullgate.NewThreatMetrixCollector(page, test.address, test.orgID, test.sessionID)
			if err == nil {
				t.Fatal("invalid collector source was accepted")
			}
			if strings.Contains(fmt.Sprintf("%#v", err), "private-") {
				t.Fatal("collector validation exposed a source credential")
			}
		})
	}
	if _, err := nullgate.NewThreatMetrixCollector(nullgate.Page{URL: "/relative"}, directCollectorURL, "org", "session"); err == nil {
		t.Fatal("invalid parent document was accepted")
	}
}

func TestProfileRejectsInvalidEntryBeforeConnecting(t *testing.T) {
	var connections, targetCalls atomic.Int32
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
		targetCalls.Add(1)
		return nullgate.TargetResponse{}, errors.New("unexpected target request")
	})
	ambiguous := collectorProfileParams(t)
	ambiguous.Protection.TagsURL = profileParams().Protection.TagsURL
	changedPage := collectorProfileParams(t)
	changedPage.Protection.Page.URL = "/relative"
	for name, params := range map[string]nullgate.ThreatMetrixParams{
		"missing entry":  {Protection: nullgate.ThreatMetrix{Page: page}},
		"both entries":   ambiguous,
		"not a tags URL": {Protection: nullgate.ThreatMetrix{Page: page, TagsURL: directCollectorURL}},
		"changed parent": changedPage,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			profile, err := session.Profile(ctx, params, target)
			if profile != nil || err == nil || connections.Load() != 0 || targetCalls.Load() != 0 {
				t.Fatalf("invalid entry reached profiling: profile=%v err=%v connections=%d target_calls=%d",
					profile, err, connections.Load(), targetCalls.Load())
			}
		})
	}
}

func TestProfileTagsAndCollectorStartContract(t *testing.T) {
	tags := profileParams()
	tags.Protection.TagsURL = "/fp/tags.js?org_id=org&session_id=source-session#local"
	for _, test := range []struct {
		name   string
		params nullgate.ThreatMetrixParams
		direct bool
	}{
		{"tags", tags, false},
		{"collector", collectorProfileParams(t), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			starts := make(chan []byte, 1)
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
					`{"type":"hello","state_id":"continuation-not-source-session","request_id":"` + profileRequestID + `"}`,
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
			target := profileTarget(t, func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error) {
				t.Error("startup contract unexpectedly requested target HTTP")
				return nullgate.TargetResponse{}, errors.New("unexpected target request")
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			profile, err := sessionFor(t, client).Profile(ctx, test.params, target)
			if err != nil {
				t.Fatal(err)
			}
			defer profile.Close()
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(<-starts, &fields); err != nil {
				t.Fatal(err)
			}
			_, hasTags := fields["tags_url"]
			_, hasCollector := fields["collector"]
			if hasTags == hasCollector || hasCollector != test.direct {
				t.Fatal("start must have exactly the selected entry source")
			}
			var website struct{ URL, HTML string }
			if err := json.Unmarshal(fields["website"], &website); err != nil || website.URL != page.URL || website.HTML != page.HTML {
				t.Fatal("direct source replaced the parent page/document")
			}
			if !test.direct {
				var tagsURL string
				if err := json.Unmarshal(fields["tags_url"], &tagsURL); err != nil || tagsURL != "https://target.example/fp/tags.js?org_id=org&session_id=source-session" {
					t.Fatal("tags entry lost its existing relative URL semantics")
				}
				return
			}
			var collector struct {
				URL       string `json:"url"`
				OrgID     string `json:"org_id"`
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(fields["collector"], &collector); err != nil {
				t.Fatal(err)
			}
			if collector.URL != directCollectorURL || collector.OrgID != "explicit-org" || collector.SessionID != "source-session" {
				t.Fatal("collector URL or explicit IDs changed at the protocol boundary")
			}
			if strings.Contains(fmt.Sprintf("%#v", test.params.Protection), "source-session") {
				t.Fatal("default rendering exposed the collector session")
			}
		})
	}
}
