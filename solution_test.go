package nullgate_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestReportOnlyDeliversRequestIDWithoutAPIOrCookieState(t *testing.T) {
	reports := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/report" {
			w.Header().Set("X-State-ID", "private-generation-state")
			http.SetCookie(w, &http.Cookie{Name: "api_cookie", Value: "private-cookie"})
			writeSensor(w)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Header.Get("X-State-ID") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("User-Agent") == "Chrome146 test agent" {
			t.Error("report leaked generation credentials, state, cookies, or browser identity")
		}
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Error(err)
		}
		reports <- data
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse(server.URL)
	jar.SetCookies(endpoint, []*http.Cookie{{Name: "caller_cookie", Value: "caller-private"}})
	httpClient := server.Client()
	httpClient.Jar = jar
	client, err := nullgate.NewClient(apiKey, nullgate.Options{BaseURL: server.URL, AnalyticsURL: server.URL, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session := sessionFor(t, client)
	solution, err := session.Solve(context.Background(), nullgate.SensorParams{Protection: sensor, Script: "source"})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := solution.Report(context.Background())
	if err != nil || !delivered {
		t.Fatalf("report delivery=%v, error=%v", delivered, err)
	}
	if actual := <-reports; !reflect.DeepEqual(actual, map[string]any{"request_id": solution.RequestID}) {
		t.Errorf("report payload contains more than the issued request ID: %v", actual)
	}
}

func TestReportRemoteStatusAndRedirectAreFalseWithoutRetry(t *testing.T) {
	for _, status := range []int{200, 204, 302, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls, redirected atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
			}))
			defer destination.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			delivered, err := clientFor(t, server).Report(context.Background(), "unknown-request-id")
			if err != nil || delivered != (status >= 200 && status < 300) {
				t.Errorf("status %d delivery=%v error=%v", status, delivered, err)
			}
			if calls.Load() != 1 || redirected.Load() != 0 {
				t.Error("report retried or followed a redirect")
			}
		})
	}
}

func TestReportNetworkFailureIsFalseButProgrammingErrorsPropagate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := clientFor(t, server)
	server.Close()
	if delivered, err := client.Report(context.Background(), "request"); err != nil || delivered {
		t.Errorf("connection refusal must be quiet false, got delivery=%v error=%v", delivered, err)
	}
	programmingFailure := errors.New("caller transport programming failure")
	for _, test := range []struct {
		failure error
		quiet   bool
	}{
		{programmingFailure, false}, {&net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}, true},
		{fmt.Errorf("local trust store failure: %w", x509.SystemRootsError{Err: programmingFailure}), false},
		{fmt.Errorf("wrapped TLS failure: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}}), true},
		{fmt.Errorf("wrapped trust failure: %w", x509.UnknownAuthorityError{Cert: &x509.Certificate{}}), true},
		{fmt.Errorf("wrapped hostname failure: %w", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "analytics.example"}), true},
		{fmt.Errorf("wrapped validity failure: %w", x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}), true},
	} {
		custom, err := nullgate.NewClient(apiKey, nullgate.Options{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, test.failure })}})
		if err != nil {
			t.Fatal(err)
		}
		delivered, reportErr := custom.Report(context.Background(), "request")
		custom.Close()
		if delivered || (test.quiet && reportErr != nil) || (!test.quiet && !errors.Is(reportErr, test.failure)) {
			t.Errorf("transport failure classification: delivery=%v error=%v", delivered, reportErr)
		}
	}
}

func TestReportUntrustedTLSCertificateIsFalseWithoutError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("report reached analytics despite an untrusted TLS certificate")
	}))
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	defer transport.CloseIdleConnections()
	client, err := nullgate.NewClient(apiKey, nullgate.Options{
		AnalyticsURL: server.URL,
		HTTPClient:   &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if delivered, err := client.Report(context.Background(), "request"); delivered || err != nil {
		t.Errorf("untrusted TLS must be quiet false, got delivery=%v error=%v", delivered, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if delivered, err := client.Report(ctx, "cancelled"); delivered || !errors.Is(err, context.Canceled) {
		t.Errorf("caller cancellation was swallowed: delivery=%v error=%v", delivered, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReportCancellationIsNotDeliveryAndInternalTimeoutIsFinite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := clientFor(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if delivered, err := client.Report(ctx, "cancelled-request"); delivered || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("caller cancellation was swallowed: delivery=%v error=%v", delivered, err)
	}
	start := time.Now()
	if delivered, err := client.Report(context.Background(), "slow-remote-request"); delivered || err != nil {
		t.Errorf("remote report timeout must be quiet false: delivery=%v error=%v", delivered, err)
	}
	if elapsed := time.Since(start); elapsed < 2500*time.Millisecond || elapsed > 6*time.Second {
		t.Errorf("anonymous report timeout is not the finite three-second deadline: %s", elapsed)
	}
}

func TestWaitUsesAbsoluteDeadlineAndPreservesCancellation(t *testing.T) {
	past := &nullgate.Solution{SendAt: -1}
	if err := past.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := time.Now().Add(30 * time.Millisecond)
	future := &nullgate.Solution{SendAt: float64(target.Unix()) + float64(target.Nanosecond())/1e9}
	if err := future.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(target.Add(-time.Microsecond)) {
		t.Error("Wait returned before the absolute submission deadline")
	}
	for _, deadline := range []float64{future.SendAt + 3600, 1e300} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := (&nullgate.Solution{SendAt: deadline}).Wait(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("future deadline %g lost cancellation or overflowed: %v", deadline, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := past.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("already-cancelled context was swallowed by immediate-ready path: %v", err)
	}
}
