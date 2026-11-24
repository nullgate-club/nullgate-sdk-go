// Package pingone generates PingOne Protect data using caller-owned target HTTP.
package pingone

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"golang.org/x/net/http/httpguts"
)

const maxTargetBytes = 32 << 20

// Client shares the authenticated API connection.
type Client struct{ connection *api.Client }

func New(connection *api.Client) *Client { return &Client{connection: connection} }

// Session owns continuation state for a browser visit.
type Session struct {
	connection *api.Client
	visit      *browser.Session
	gate       chan struct{}
	page       *browser.Page
	digest     [32]byte
	state      string
}

func (*Session) String() string     { return "pingone.Session{<redacted>}" }
func (s *Session) GoString() string { return s.String() }

func (c *Client) Session(visit *browser.Session) (*Session, error) {
	if c.connection.Closed() {
		return nil, api.ErrClosed
	}
	if visit == nil {
		return nil, api.NewError("invalid_request", "browser session must not be nil")
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Session{connection: c.connection, visit: visit, gate: gate}, nil
}

// Options supplies the source and caller-owned target request function.
// SDKConfig uses the original PingOne start() option names.
type Options struct {
	Script              string
	Send                func(*http.Request) (*http.Response, error)
	SDKConfig           map[string]any
	ClientToken         string
	JWTDeviceAttributes string
	JWTAgentPayload     string
	TokenHost           string
	Behavioral          any
}

func (Options) String() string     { return "pingone.Options{<redacted>}" }
func (o Options) GoString() string { return o.String() }

// Result contains the generated value and its identifiers.
type Result struct {
	Data       string `json:"data"`
	SDKVersion string `json:"sdk_version"`
	DeviceID   string `json:"device_id"`
	RequestID  string `json:"request_id"`
}

func (Result) String() string     { return "pingone.Result{Data:<redacted>}" }
func (r Result) GoString() string { return r.String() }

type prepared struct {
	Session string `json:"session"`
	Request struct {
		Role        string            `json:"role"`
		Method      string            `json:"method"`
		URL         string            `json:"url"`
		Headers     map[string]string `json:"headers"`
		Body        *string           `json:"body"`
		Credentials string            `json:"credentials"`
	} `json:"request"`
}

type protected struct {
	Result
	Session string `json:"session"`
}

// Protect generates data, fetching a client token through Send unless supplied.
func (s *Session) Protect(ctx context.Context, page *browser.Page, opts Options) (*Result, error) {
	if ctx == nil {
		return nil, api.NewError("invalid_request", "Context must not be nil")
	}
	if page == nil || page.Session() != s.visit {
		return nil, api.NewError("invalid_request", "page belongs to a different browser session")
	}
	if opts.Script == "" {
		return nil, api.NewError("invalid_request", "script must not be empty")
	}
	if opts.ClientToken == "" && opts.Send == nil {
		return nil, api.NewError("invalid_request", "send must not be nil without a client token")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.connection.Done():
		return nil, api.ErrClosed
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.connection.Closed() {
		return nil, api.ErrClosed
	}
	digest := sha256.Sum256([]byte(opts.Script))
	retained := s.page == page && s.digest == digest
	body := map[string]any{
		"profile": s.visit.Profile(), "user_agent": s.visit.UserAgent(),
		"website": map[string]any{"url": page.URL(), "html": page.HTML(), "document_id": page.DocumentID(), "started_at_ms": page.StartedAtMS()},
		"script":  opts.Script,
	}
	if s.state != "" {
		body["session"] = s.state
		if retained {
			delete(body, "script")
		}
	}
	if zone := s.visit.Timezone(); zone != nil {
		body["timezone"] = *zone
	}
	if opts.SDKConfig != nil {
		body["sdk_config"] = opts.SDKConfig
	}
	if opts.TokenHost != "" {
		body["token_host"] = opts.TokenHost
	}
	if opts.ClientToken != "" {
		body["client_token"] = opts.ClientToken
	} else {
		var prep prepared
		if err := s.connection.Call(ctx, "/pingone/prepare", body, &prep, opts.Script, true); err != nil {
			return nil, err
		}
		if prep.Session == "" {
			return nil, api.ProtocolError("Missing response session")
		}
		s.state = prep.Session
		body["session"] = prep.Session
		delete(body, "script")
		text, err := s.target(ctx, opts.Send, prep)
		if err != nil {
			return nil, err
		}
		body["token_response"] = text
	}
	if opts.JWTDeviceAttributes != "" {
		body["jwt_device_attributes"] = opts.JWTDeviceAttributes
	}
	if opts.JWTAgentPayload != "" {
		body["jwt_agent_payload"] = opts.JWTAgentPayload
	}
	if opts.Behavioral != nil {
		body["behavioral"] = opts.Behavioral
	}
	var result protected
	if err := s.connection.Call(ctx, "/pingone/protect", body, &result, opts.Script, true); err != nil {
		return nil, err
	}
	if result.Session == "" || result.Data == "" || result.SDKVersion == "" || result.DeviceID == "" || result.RequestID == "" {
		return nil, api.ProtocolError("Malformed protect response")
	}
	s.state = result.Session
	s.page = page
	s.digest = digest
	return &result.Result, nil
}

func (s *Session) target(ctx context.Context, send func(*http.Request) (*http.Response, error), prep prepared) (string, error) {
	r := prep.Request
	if r.Role != "pingone.token" || r.Method != http.MethodGet || r.Body != nil || r.Credentials != "include" {
		return "", api.ProtocolError("Invalid token request")
	}
	if _, err := api.AbsoluteHTTPURL(r.URL); err != nil {
		return "", api.ProtocolError("Invalid token request URL")
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, nil)
	if err != nil {
		return "", api.ProtocolError("Invalid token request")
	}
	for key, value := range r.Headers {
		if !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(value) {
			return "", api.ProtocolError("Invalid token request headers")
		}
		req.Header[key] = []string{value}
	}
	if err := s.connection.CheckTargetCredentials(r.URL, req.Header); err != nil {
		return "", err
	}
	resp, err := send(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return "", &api.Error{Code: "target_error", Message: "Token request failed", Cause: err}
	}
	if resp == nil {
		return "", api.ProtocolError("Missing token response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &api.Error{Code: "target_error", Message: fmt.Sprintf("Token request returned status %d", resp.StatusCode), Status: resp.StatusCode}
	}
	if resp.Body == nil {
		return "", api.ProtocolError("Missing token response body")
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTargetBytes+1))
	if readErr != nil {
		return "", &api.Error{Code: "target_error", Message: "Cannot read token response", Cause: readErr}
	}
	if len(data) > maxTargetBytes {
		return "", api.ProtocolError("Token response exceeds 32 MiB")
	}
	if !utf8.Valid(data) {
		return "", api.ProtocolError("Token response is not UTF-8")
	}
	return string(data), nil
}
