package api

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const DefaultBaseURL = "https://api.nullgate.club"

// Options applies only to the Nullgate API, never to target requests.
// HTTPClient is copied. Its transport stays caller-owned; cookies and redirects are disabled.
type Options struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
}

// New validates configuration without network I/O. An empty key reads NULLGATE_API_KEY.
func New(key string, options Options) (*Client, error) {
	if key == "" {
		key = os.Getenv("NULLGATE_API_KEY")
	}
	if !strings.HasPrefix(key, "ng_") || len(key) <= 3 || strings.ContainsAny(key, " \t\r\n") {
		return nil, NewError("invalid_request", "API key must be an ng_ credential without whitespace")
	}
	base := options.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := AbsoluteHTTPURL(base)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, NewError("invalid_url", "BaseURL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout < 0 {
		return nil, NewError("invalid_request", "Timeout must be positive")
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
	dialer := websocket.Dialer{HandshakeTimeout: timeout}
	// Snapshot before HTTP starts: net/http can initialize its TLS/ALPN settings lazily.
	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		dialer.NetDialContext = transport.DialContext
		if transport.TLSClientConfig != nil {
			dialer.TLSClientConfig = transport.TLSClientConfig.Clone()
			dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &Client{key: key, baseURL: strings.TrimRight(u.String(), "/"), http: &httpClient, timeout: timeout, ownsTransport: owns, websocket: dialer, done: make(chan struct{}), lifetime: lifetime, cancel: cancel}, nil
}

// AbsoluteHTTPURL validates an HTTP boundary without accepting URL credentials.
func AbsoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, NewError("invalid_url", "Expected an absolute HTTP(S) URL without credentials")
	}
	return u, nil
}
