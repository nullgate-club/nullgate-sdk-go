// Package solver calls the local Nullgate HTTP API.
package solver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Product identifies a supported solver.
type Product string

const (
	Akamai       Product = "akamai"
	ThreatMetrix Product = "threatmetrix"
	PingOne      Product = "pingone"
	AmazonACIC   Product = "amazon_acic"
)

// Options configures the local API client. An injected HTTPClient remains caller-owned.
type Options struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client sends solve requests to the local API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New creates a client. The default server is http://127.0.0.1:8191.
func New(options Options) (*Client, error) {
	baseURL := options.BaseURL
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8191"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, &Error{Code: "invalid_request", Message: "base URL must be an absolute HTTP(S) URL without credentials, query, or fragment", Stage: "client"}
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 190 * time.Second}
	}
	// Redirects could replay a paid solve or send it to another host.
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: &clientCopy}, nil
}

// Cookie carries the attributes needed to restore a target cookie.
type Cookie struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secure   bool     `json:"secure"`
	HTTPOnly bool     `json:"http_only"`
	Expires  *float64 `json:"expires"`
	HostOnly *bool    `json:"host_only,omitempty"`
	SameSite string   `json:"same_site,omitempty"`
}

// Transport configures target HTTP emulation and native TLS and HTTP/2 options.
type Transport struct {
	Emulation    string         `json:"emulation,omitempty"`
	TLSOptions   map[string]any `json:"tls_options,omitempty"`
	HTTP2Options map[string]any `json:"http2_options,omitempty"`
	HeadersOrder []string       `json:"headers_order,omitempty"`
}

// Collector supplies an explicitly discovered ThreatMetrix collector.
type Collector struct {
	URL       string `json:"url"`
	OrgID     string `json:"org_id"`
	SessionID string `json:"session_id"`
}

// PingOneOptions supplies optional PingOne Protect inputs.
type PingOneOptions struct {
	SDKConfig           map[string]any `json:"sdk_config,omitempty"`
	JWTDeviceAttributes string         `json:"jwt_device_attributes,omitempty"`
	JWTAgentPayload     string         `json:"jwt_agent_payload,omitempty"`
	ClientToken         string         `json:"client_token,omitempty"`
	TokenHost           string         `json:"token_host,omitempty"`
	Behavioral          map[string]any `json:"behavioral,omitempty"`
}

// Request describes a target visit. UserAgent is required for a new session or one-shot solve.
type Request struct {
	Type        Product           `json:"type"`
	URL         string            `json:"url"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Proxy       string            `json:"proxy,omitempty"`
	Session     string            `json:"session,omitempty"`
	Cookies     []Cookie          `json:"cookies"`
	Transport   *Transport        `json:"transport,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ScriptURL   string            `json:"script_url,omitempty"`
	HTML        string            `json:"html,omitempty"`
	PixelIframe bool              `json:"pixel_iframe,omitempty"`
	Collector   *Collector        `json:"collector,omitempty"`
	PingOne     *PingOneOptions   `json:"pingone,omitempty"`
}

// ProductResult contains the fields returned by supported products.
type ProductResult struct {
	Accepted   bool   `json:"accepted"`
	Collected  bool   `json:"collected"`
	Data       string `json:"data"`
	DeviceID   string `json:"device_id"`
	SDKVersion string `json:"sdk_version"`
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// Result contains target cookies and product-specific output.
type Result struct {
	Cookies []Cookie      `json:"cookies"`
	Result  ProductResult `json:"result"`
}

// Error describes a local API or transport failure. Cause contains the server's optional cause.
// Unwrap preserves context cancellation and transport errors without printing their details.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Stage     string `json:"stage"`
	RequestID string `json:"request_id"`
	Cause     string `json:"cause"`
	Status    int    `json:"-"`
	err       error
}

func (e *Error) Error() string {
	message := "solver: " + e.Code + ": " + e.Message
	if e.Status != 0 {
		message += fmt.Sprintf(" (status=%d)", e.Status)
	}
	if e.Stage != "" {
		message += " stage=" + e.Stage
	}
	if e.RequestID != "" {
		message += " request_id=" + e.RequestID
	}
	return message
}

func (e *Error) Unwrap() error { return e.err }

// Solve calls the local API once. It never retries a paid solve.
func (c *Client) Solve(ctx context.Context, request Request) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 190*time.Second)
	defer cancel()
	var result Result
	body, err := json.Marshal(request)
	if err != nil {
		return result, &Error{Code: "invalid_request", Message: "cannot encode request", Stage: "client", err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/solve", bytes.NewReader(body))
	if err != nil {
		return result, &Error{Code: "invalid_request", Message: "cannot create request", Stage: "client", err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		code := "transport_error"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "timeout"
		} else if errors.Is(err, context.Canceled) {
			code = "cancelled"
		}
		return result, &Error{Code: code, Message: "local API request failed; check the server and request deadline", Stage: "transport", err: err}
	}
	defer resp.Body.Close()
	const maxResponse = 4 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return result, &Error{Code: "transport_error", Message: "cannot read local API response", Stage: "transport", Status: resp.StatusCode, err: err}
	}
	if len(data) > maxResponse {
		return result, &Error{Code: "invalid_response", Message: "local API response exceeds size limit", Stage: "response", Status: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiError Error
		if json.Unmarshal(data, &apiError) == nil && apiError.Code != "" && apiError.Message != "" && apiError.Stage != "" && apiError.RequestID != "" {
			apiError.Status = resp.StatusCode
			return result, &apiError
		}
		return result, &Error{Code: "invalid_response", Message: "local API returned an invalid error response", Stage: "response", Status: resp.StatusCode}
	}
	var envelope struct {
		Cookies []Cookie       `json:"cookies"`
		Result  *ProductResult `json:"result"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Cookies == nil || envelope.Result == nil {
		return Result{}, &Error{Code: "invalid_response", Message: "local API returned an invalid solve response", Stage: "response", Status: resp.StatusCode}
	}
	output := envelope.Result
	if request.Type == Akamai && !output.Accepted ||
		request.Type == ThreatMetrix && !output.Collected ||
		request.Type == PingOne && (output.Data == "" || output.DeviceID == "" || output.SDKVersion == "" || output.RequestID == "") ||
		request.Type == AmazonACIC && (output.Status != "PASS" || output.URL == "" || output.StatusCode < 200 || output.StatusCode >= 300) {
		return Result{}, &Error{Code: "invalid_response", Message: "local API returned incomplete product data", Stage: "response", Status: resp.StatusCode}
	}
	for _, cookie := range envelope.Cookies {
		if cookie.Name == "" {
			return Result{}, &Error{Code: "invalid_response", Message: "local API returned an invalid cookie", Stage: "response", Status: resp.StatusCode}
		}
	}
	return Result{Cookies: envelope.Cookies, Result: *output}, nil
}
