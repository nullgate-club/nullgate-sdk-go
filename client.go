package nullgate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultBaseURL      = "https://akamai.nullgate.club"
	DefaultAnalyticsURL = "https://analytics.nullgate.club"
	reportTimeout       = 3 * time.Second
)

// Options configures only the Nullgate API, never the target website transport.
// HTTPClient is copied, with redirects and its cookie jar disabled. Its
// RoundTripper remains caller-owned and must be safe for concurrent requests.
type Options struct {
	BaseURL      string
	AnalyticsURL string
	HTTPClient   *http.Client
}

// Client owns a reusable API transport. Sessions keep their state independently.
// Use defer client.Close(); closing a client does not close a supplied transport.
type Client struct {
	apiKey        string
	baseURL       string
	analyticsURL  string
	http          *http.Client
	ownsTransport bool
	closed        atomic.Bool
}

func (c *Client) String() string   { return "nullgate.Client{APIKey:<redacted>}" }
func (c *Client) GoString() string { return c.String() }

// NewClient validates configuration without making any network requests.
func NewClient(apiKey string, options Options) (*Client, error) {
	if !strings.HasPrefix(apiKey, "ng_") || strings.TrimSpace(apiKey) != apiKey || strings.ContainsAny(apiKey, "\r\n\t ") {
		return nil, errors.New("nullgate: API key must be an ng_ credential without whitespace")
	}
	if options.BaseURL == "" {
		options.BaseURL = DefaultBaseURL
	}
	if options.AnalyticsURL == "" {
		options.AnalyticsURL = DefaultAnalyticsURL
	}
	base, err := apiBase(options.BaseURL)
	if err != nil {
		return nil, errors.New("nullgate: BaseURL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	analytics, err := apiBase(options.AnalyticsURL)
	if err != nil {
		return nil, errors.New("nullgate: AnalyticsURL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	var api http.Client
	ownsTransport := false
	if options.HTTPClient != nil {
		api = *options.HTTPClient
	} else if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		api.Transport = transport.Clone()
		ownsTransport = true
	}
	if api.Timeout <= 0 {
		api.Timeout = 30 * time.Second
	}
	api.Jar = nil
	api.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{apiKey: apiKey, baseURL: base, analyticsURL: analytics, http: &api, ownsTransport: ownsTransport}, nil
}

func apiBase(raw string) (string, error) {
	u, err := absoluteHTTPURL(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("invalid API base URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// SessionOptions binds one isolated continuation stream to a UUID and browser
// user agent. A non-nil Timezone is sent unchanged on each generation request.
type SessionOptions struct {
	Identity  string
	UserAgent string
	Timezone  *string
}

// Session serializes generation while permitting independent sessions to share
// the client's connection pool. Its mutex protects state and its context-aware
// gate lets callers cancel while another generation is in flight.
type Session struct {
	client    *Client
	identity  string
	userAgent string
	timezone  *string
	gate      chan struct{}
	mu        sync.Mutex
	stateID   string
	hasState  bool
	closed    bool
}

func (s *Session) String() string   { return "nullgate.Session{State:<redacted>}" }
func (s *Session) GoString() string { return s.String() }

// Open creates a new state stream without contacting the service.
func (c *Client) Open(options SessionOptions) (*Session, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	identity, err := uuid.Parse(options.Identity)
	if err != nil {
		return nil, errors.New("nullgate: Identity must be a UUID")
	}
	if strings.TrimSpace(options.UserAgent) == "" || strings.ContainsAny(options.UserAgent, "\r\n") {
		return nil, errors.New("nullgate: UserAgent must be a nonempty HTTP header value")
	}
	var timezone *string
	if options.Timezone != nil {
		value := *options.Timezone
		timezone = &value
	}
	return &Session{client: c, identity: identity.String(), userAgent: options.UserAgent, timezone: timezone, gate: make(chan struct{}, 1)}, nil
}

// Solve calls only Nullgate. It neither sends to the target nor retries a
// generation. Continuation headers are retained even on API/protocol failures.
func (s *Session) Solve(ctx context.Context, params Params) (*Solution, error) {
	if ctx == nil {
		return nil, errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	stateID, hasState, closed := s.stateID, s.hasState, s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return nil, ErrClosed
	}
	operation, payload, target, err := generationPayload(params, s.timezone)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("nullgate: generation params must contain JSON-serializable values")
	}
	endpoint := s.client.baseURL + "/v1/" + s.identity + "/generate?type=" + operation
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	request.GetBody = nil // Do not replay a failed POST on a reused connection.
	request.Header.Set("Authorization", "Bearer "+s.client.apiKey)
	request.Header.Set("User-Agent", s.userAgent)
	request.Header.Set("Content-Type", "application/json")
	if hasState {
		request.Header.Set("X-State-ID", stateID)
	}
	response, err := s.client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	defer response.Body.Close()
	s.mu.Lock()
	if values, exists := response.Header[http.CanonicalHeaderKey("X-State-ID")]; exists && !s.closed {
		s.stateID = ""
		if len(values) > 0 {
			s.stateID = values[0]
		}
		s.hasState = true
	}
	closed = s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return nil, ErrClosed
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, responseError(response, data)
	}
	return normalizeSolution(response, data, operation, target, s.client)
}

// Close discards this stream's state. It is safe to call repeatedly and does
// not close the client. In-flight requests remain governed by their contexts.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed, s.hasState, s.stateID = true, false, ""
	return nil
}

// Close prevents new API calls and closes owned idle connections. Cancel the
// caller's contexts to stop active requests. Caller-supplied pools stay open.
func (c *Client) Close() error {
	if !c.closed.Swap(true) && c.ownsTransport {
		c.http.CloseIdleConnections()
	}
	return nil
}

// Report delivers only {request_id} to analytics, without authorization, state,
// target cookies, redirects, or retries. True means HTTP delivery, not archive
// acceptance, target failure attribution, or a refund. Remote/network failure
// returns false,nil; caller cancellation and programming errors remain errors.
func (c *Client) Report(ctx context.Context, requestID string) (bool, error) {
	if ctx == nil {
		return false, errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if c.closed.Load() {
		return false, ErrClosed
	}
	if requestID == "" {
		return false, errors.New("nullgate: request ID must not be empty")
	}
	body, _ := json.Marshal(struct {
		RequestID string `json:"request_id"`
	}{RequestID: requestID})
	reportCtx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(reportCtx, http.MethodPost, c.analyticsURL+"/report", bytes.NewReader(body))
	if err != nil {
		return false, &TransportError{Operation: "report", Err: err}
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if reportCtx.Err() != nil || remoteFailure(err) {
			return false, nil
		}
		return false, &TransportError{Operation: "report", Err: err}
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		if reportCtx.Err() != nil || remoteFailure(err) {
			return false, nil
		}
		return false, &TransportError{Operation: "report", Err: err}
	}
	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

func remoteFailure(err error) bool {
	var request *url.Error
	if errors.As(err, &request) {
		err = request.Err
	}
	var network net.Error
	var protocol *http.ProtocolError
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	return errors.As(err, &network) || errors.As(err, &protocol) ||
		errors.As(err, &verification) || errors.As(err, &authority) ||
		errors.As(err, &hostname) || errors.As(err, &certificate) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func responseError(response *http.Response, body []byte) *APIError {
	var detail any
	if err := json.Unmarshal(body, &detail); err != nil {
		detail = string(body)
	} else if object, ok := detail.(map[string]any); ok {
		if value, exists := object["detail"]; exists {
			detail = value
		}
	}
	return &APIError{StatusCode: response.StatusCode, Detail: detail, RequestID: response.Header.Get("X-Request-ID")}
}
