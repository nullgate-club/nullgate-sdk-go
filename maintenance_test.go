package nullgate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const updatingBody = `{"detail":"Service updating; retry after a short delay"}`

func maintenanceSession(t *testing.T, options Options) *Session {
	t.Helper()
	client, err := NewClient("ng_test", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.Open(SessionOptions{Identity: "00000000-0000-4000-8000-000000000001", UserAgent: "test agent"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestMaintenanceRetryBoundaryAndResponseOwnership(t *testing.T) {
	for _, test := range []struct {
		name, retryAfter, body, marker string
		status                         int
		retries                        bool
	}{
		{"definitive", "0", updatingBody, "1", 503, true},
		{"conflicting body", "0", `{"detail":"unavailable"}`, "1", 503, true},
		{"legacy body only", "0", updatingBody, "", 503, false},
		{"unrelated 503", "0", `{"detail":"unavailable"}`, "", 503, false},
		{"wrong marker", "0", updatingBody, "true", 503, false},
		{"502", "0", updatingBody, "1", 502, false},
		{"missing header", "", updatingBody, "1", 503, false},
		{"too long", "6", updatingBody, "1", 503, false},
		{"negative", "-1", updatingBody, "1", 503, false},
		{"infinity", "Inf", updatingBody, "1", 503, false},
		{"not number", "tomorrow", updatingBody, "1", 503, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			var state string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if state != "" && state != r.Header.Get("X-State-ID") {
					t.Error("maintenance changed continuation")
				}
				state = r.Header.Get("X-State-ID")
				body, err := io.ReadAll(r.Body)
				if err != nil || !strings.Contains(string(body), `"performance_timing"`) {
					t.Error("request body lost on retry")
				}
				w.Header().Set("Retry-After", test.retryAfter)
				w.Header().Set("X-Nullgate-Maintenance", test.marker)
				w.Header().Set("X-State-ID", "must-not-adopt")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			session := maintenanceSession(t, Options{AmazonBaseURL: server.URL})
			initial := session.amazonStateID
			_, err := session.Fwcim(context.Background(), fwcimTestParams())
			var apiError *APIError
			if !errors.As(err, &apiError) {
				t.Fatalf("expected original API error, got %v", err)
			}
			want := 1
			if test.retries {
				want = 3
			}
			if calls.Load() != int32(want) {
				t.Fatalf("got %d calls, want %d", calls.Load(), want)
			}
			if test.retries && session.amazonStateID != initial {
				t.Fatal("final maintenance response changed continuation")
			}
		})
	}
}

func TestMaintenanceRetrySuccessAndCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.Header().Set("X-Nullgate-Maintenance", "1")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(updatingBody))
			return
		}
		w.Header().Set("X-Request-ID", "success")
		_, _ = w.Write([]byte(`{"sensor_data":"ok","send_at":0,"headers":{}}`))
	}))
	defer server.Close()
	session := maintenanceSession(t, Options{BaseURL: server.URL})
	params := SensorParams{Protection: Sensor{Page: fwcimTestParams().Page, ScriptURL: "https://example.com/sensor"}, Script: "source"}
	if _, err := session.Solve(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("definitive maintenance rejection not retried")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.waitMaintenance(ctx, 5*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.waitMaintenance(context.Background(), 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestMaintenanceRetryStopsDuringDelay(t *testing.T) {
	var calls atomic.Int32
	denied := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "5")
		w.Header().Set("X-Nullgate-Maintenance", "1")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(updatingBody))
		denied <- struct{}{}
	}))
	defer server.Close()
	session := maintenanceSession(t, Options{AmazonBaseURL: server.URL})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := session.Fwcim(ctx, fwcimTestParams()); result <- err }()
	<-denied
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("request retried after cancellation")
	}
}

type maintenanceTransport func(*http.Request) (*http.Response, error)

func (f maintenanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMaintenanceNeverRetriesTransportFailure(t *testing.T) {
	calls := 0
	failure := errors.New("connection failed after possible work")
	session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, failure
	})}})
	if _, err := session.Fwcim(context.Background(), fwcimTestParams()); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("ambiguous transport failure retried")
	}
}

func TestProfileMaintenanceHandshakeRetriesOnlyExactDenial(t *testing.T) {
	for _, definitive := range []bool{false, true} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "0")
			if definitive {
				w.Header().Set("X-Nullgate-Maintenance", "1")
			}
			w.WriteHeader(503)
			if definitive {
				_, _ = w.Write([]byte(updatingBody))
			} else {
				_, _ = w.Write([]byte(`{"detail":"unavailable"}`))
			}
		}))
		session := maintenanceSession(t, Options{ProfileBaseURL: server.URL})
		target, err := NewTarget(func(context.Context, TargetRequest) (TargetResponse, error) {
			t.Error("denied handshake must not issue target requests")
			return TargetResponse{}, nil
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = session.Profile(context.Background(), ThreatMetrixParams{Protection: ThreatMetrix{
			Page: fwcimTestParams().Page, TagsURL: "https://tags.example/tags.js?org_id=org&session_id=session",
		}}, target)
		if err == nil {
			t.Fatal("expected denied handshake error")
		}
		want := 1
		if definitive {
			want = 3
		}
		if calls.Load() != int32(want) {
			t.Fatalf("handshake attempts: got %d want %d", calls.Load(), want)
		}
		server.Close()
	}
}

type unreadMaintenanceBody struct {
	t *testing.T
}

func (body unreadMaintenanceBody) Read([]byte) (int, error) {
	body.t.Error("maintenance classifier read response body")
	return 0, io.ErrUnexpectedEOF
}

func (unreadMaintenanceBody) Close() error { return nil }

func TestMaintenanceClassificationNeverReadsBody(t *testing.T) {
	for _, marker := range []string{"", "1", "true"} {
		response := &http.Response{StatusCode: 503, Header: make(http.Header), Body: unreadMaintenanceBody{t}}
		response.Header.Set("Retry-After", "0.25")
		response.Header.Set("X-Nullgate-Maintenance", marker)
		delay, retry := maintenanceDelay(response)
		if retry != (marker == "1") || (retry && delay != 250*time.Millisecond) {
			t.Fatalf("wrong header decision: %v %v", delay, retry)
		}
		response.Header.Add("X-Nullgate-Maintenance", "1")
		if _, retry := maintenanceDelay(response); retry {
			t.Fatal("accepted duplicate maintenance markers")
		}
	}
}

func TestMaintenanceWaitWakesOnOwnerClose(t *testing.T) {
	for _, owner := range []string{"client", "session"} {
		t.Run(owner, func(t *testing.T) {
			session := maintenanceSession(t, Options{})
			result := make(chan error, 1)
			go func() { result <- session.waitMaintenance(context.Background(), 5*time.Second) }()
			select {
			case err := <-result:
				t.Fatalf("maintenance wait returned before close: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if owner == "client" {
				_ = session.client.Close()
			} else {
				_ = session.Close()
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("maintenance wait did not wake on close")
			}
		})
	}
}

type truncatedGenerationBody struct{}

func (truncatedGenerationBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (truncatedGenerationBody) Close() error             { return nil }

func TestUnmarked503RetainsStateBeforeTruncatedBody(t *testing.T) {
	for _, provider := range []string{"akamai", "amazon"} {
		t.Run(provider, func(t *testing.T) {
			calls := 0
			session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 503, Header: http.Header{"X-State-Id": []string{"rotated"}, "Retry-After": []string{"0"}}, Body: truncatedGenerationBody{}}, nil
			})}})
			var err error
			if provider == "amazon" {
				_, err = session.Fwcim(context.Background(), fwcimTestParams())
				if session.amazonStateID != "rotated" {
					t.Fatal("Amazon continuation lost on body failure")
				}
			} else {
				_, err = session.Solve(context.Background(), SensorParams{Protection: Sensor{Page: fwcimTestParams().Page, ScriptURL: "https://example.com/sensor"}, Script: "source"})
				if session.stateID != "rotated" {
					t.Fatal("Akamai continuation lost on body failure")
				}
			}
			if !errors.Is(err, io.ErrUnexpectedEOF) || calls != 1 {
				t.Fatalf("unmarked response retried or body failure lost: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestMaintenanceRejectsAmbiguousRetryAfter(t *testing.T) {
	for _, values := range [][]string{{"0", "0"}, {"0", "1"}, {"0, 1"}} {
		response := &http.Response{StatusCode: 503, Header: http.Header{
			"X-Nullgate-Maintenance": {"1"}, "Retry-After": values,
		}}
		if _, retry := maintenanceDelay(response); retry {
			t.Fatal("ambiguous retry delay accepted")
		}
	}
}

func TestGenerationChecksCloseImmediatelyBeforeDo(t *testing.T) {
	for _, owner := range []string{"session", "client"} {
		t.Run(owner, func(t *testing.T) {
			session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(*http.Request) (*http.Response, error) {
				t.Error("closed owner issued HTTP")
				return nil, errors.New("unexpected request")
			})}})
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			if owner == "session" {
				_ = session.Close()
			} else {
				_ = session.client.Close()
			}
			if _, err := session.generationRequest(request, []byte("{}")); !errors.Is(err, ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestGenerationCloseDuringMaintenanceDoesNotRetry(t *testing.T) {
	for _, owner := range []string{"session", "client"} {
		t.Run(owner, func(t *testing.T) {
			denied := make(chan struct{})
			var calls atomic.Int32
			session := maintenanceSession(t, Options{HTTPClient: &http.Client{Transport: maintenanceTransport(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				close(denied)
				return &http.Response{StatusCode: 503, Header: http.Header{
					"X-Nullgate-Maintenance": {"1"}, "Retry-After": {"5"},
				}, Body: io.NopCloser(strings.NewReader(updatingBody))}, nil
			})}})
			result := make(chan error, 1)
			go func() { _, err := session.Fwcim(context.Background(), fwcimTestParams()); result <- err }()
			<-denied
			if owner == "session" {
				_ = session.Close()
			} else {
				_ = session.client.Close()
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("closed owner did not stop maintenance")
			}
			if calls.Load() != 1 {
				t.Fatal("closed owner retried generation")
			}
		})
	}
}
