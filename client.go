// Package nullgate prepares browser-derived target requests through the Nullgate API.
// The caller owns target HTTP, cookies, proxies, and request submission.
package nullgate

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/api"
)

const DefaultBaseURL = "https://api.nullgate.club"

// Options configures the API connection, never the target transport.
// HTTPClient is copied. Its transport stays caller-owned, while redirects and cookies are disabled.
type Options struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
}

// Client is safe for concurrent use. Sessions keep independent continuation streams.
type Client struct {
	api           *api.Client
	ownsTransport bool
	profilesMu    sync.Mutex
	profiles      map[*Profile]struct{}
}

func (*Client) String() string     { return "nullgate.Client{APIKey:<redacted>}" }
func (c *Client) GoString() string { return c.String() }

// NewClient validates configuration without network I/O.
// An empty key reads NULLGATE_API_KEY. The default timeout is 30 seconds.
func NewClient(apiKey string, options Options) (*Client, error) {
	if apiKey == "" {
		apiKey = os.Getenv("NULLGATE_API_KEY")
	}
	if !strings.HasPrefix(apiKey, "ng_") || len(apiKey) <= 3 || strings.ContainsAny(apiKey, " \t\r\n") {
		return nil, newError("invalid_request", "API key must be an ng_ credential without whitespace")
	}
	base := options.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := absoluteHTTPURL(base)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, newError("invalid_url", "BaseURL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout < 0 {
		return nil, newError("invalid_request", "Timeout must be positive")
	}
	var httpClient http.Client
	owns := false
	if options.HTTPClient != nil {
		httpClient = *options.HTTPClient
	} else if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		httpClient.Transport = transport.Clone()
		owns = true
	} else {
		httpClient.Transport = http.DefaultTransport
	}
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if httpClient.Timeout == 0 || httpClient.Timeout > timeout {
		httpClient.Timeout = timeout
	}
	return &Client{api: api.New(apiKey, strings.TrimRight(u.String(), "/"), &httpClient, timeout), ownsTransport: owns, profiles: make(map[*Profile]struct{})}, nil
}

func absoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, newError("invalid_url", "Expected an absolute HTTP(S) URL without credentials")
	}
	return u, nil
}

// Close stops active profiles and requests, and closes only SDK-owned idle connections.
func (c *Client) Close() error {
	if !c.api.Close() {
		return nil
	}
	c.profilesMu.Lock()
	active := make([]*Profile, 0, len(c.profiles))
	for p := range c.profiles {
		active = append(active, p)
	}
	c.profilesMu.Unlock()
	for _, p := range active {
		_ = p.Close()
	}
	if c.ownsTransport {
		c.api.HTTP.CloseIdleConnections()
	}
	return nil
}

// Public errors keep one contract, independent of private wire implementations.
func publicError(err error) error {
	if errors.Is(err, api.ErrClosed) {
		return ErrClosed
	}
	var value *api.Error
	if errors.As(err, &value) {
		return &Error{Code: value.Code, Message: value.Message, RequestID: value.RequestID, Status: value.Status, Cause: value.Cause}
	}
	return err
}
func (c *Client) call(ctx context.Context, path string, body map[string]any, out any, script string, retry bool) error {
	return publicError(c.api.Call(ctx, path, body, out, script, retry))
}

// Report records a request ID. True means HTTP delivery, not acceptance or a refund.
func (c *Client) Report(ctx context.Context, requestID string) (bool, error) {
	if requestID == "" {
		return false, newError("invalid_request", "RequestID must not be empty")
	}
	delivered, err := c.api.Report(ctx, requestID)
	return delivered, publicError(err)
}
