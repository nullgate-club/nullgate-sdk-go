package nullgate

import (
	"context"
	"encoding/base64"
	"errors"
	"net"

	"github.com/nullgate-club/nullgate-sdk-go/internal/profilewire"
	"github.com/nullgate-club/nullgate-sdk-go/internal/turn"
	"golang.org/x/net/http/httpguts"
)

// CredentialsMode is the native request's cookie policy, not an SDK default.
type CredentialsMode string

const (
	CredentialsInclude CredentialsMode = "include"
	CredentialsOmit    CredentialsMode = "omit"
)

// TargetRequest describes one native target request. Body is raw bytes; nil is
// absent and a non-nil empty slice is a present empty body. Fetch must honor
// CredentialsOmit without sending or retaining cookies, including on redirects.
// Do not clear or replace the caller's shared jar to implement omission.
type TargetRequest struct {
	Role        string
	URL         string
	Method      string
	Headers     map[string]string
	Body        []byte
	Credentials CredentialsMode
}

func (TargetRequest) String() string {
	return "nullgate.TargetRequest{URL:<redacted>, Headers:<redacted>, Body:<redacted>}"
}
func (r TargetRequest) GoString() string { return r.String() }

// TargetResponse contains actual HTTP facts, including non-2xx status codes.
// Body must contain the original bytes, not a text conversion or base64 string.
// The caller's HTTP provider owns receiving and retaining allowed cookies.
type TargetResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

func (TargetResponse) String() string {
	return "nullgate.TargetResponse{Headers:<redacted>, Body:<redacted>}"
}
func (r TargetResponse) GoString() string { return r.String() }

// TargetFetch must be safe for concurrent calls and stop when ctx is canceled.
// HTTP error statuses are responses; connection failures are returned as errors.
type TargetFetch func(ctx context.Context, request TargetRequest) (TargetResponse, error)

// Target keeps the target's HTTP provider and TURN route local to the caller.
// Construct it with NewTarget so a proxy/direct choice is explicit and validated
// before a paid profile begins. It does not own or close the HTTP provider.
type Target struct {
	fetch TargetFetch
	dial  func(context.Context, string, string) (net.Conn, error)
}

func (Target) String() string     { return "nullgate.Target{Fetch:<redacted>, Proxy:<redacted>}" }
func (t Target) GoString() string { return t.String() }

// NewTarget accepts an explicit proxy URL or "" for direct TURN/TCP. Supported
// proxies are socks5, socks5h, http and https. Fetch must already use the same
// chosen network route. Neither proxy settings nor credentials reach Nullgate,
// and a failed proxy never falls back to a direct connection.
func NewTarget(fetch TargetFetch, proxyURL string) (Target, error) {
	if fetch == nil {
		return Target{}, errors.New("nullgate: Target requires a fetch callback")
	}
	dial, err := turn.NewDialer(proxyURL)
	if err != nil {
		return Target{}, err
	}
	return Target{fetch: fetch, dial: dial}, nil
}

func targetRequest(request *profilewire.HTTPRequest) (TargetRequest, error) {
	invalid := errors.New("invalid target request")
	address, err := absoluteHTTPURL(request.URL)
	credentials := CredentialsMode(request.Credentials)
	if err != nil || address.User != nil || request.Role == "" ||
		!httpguts.ValidHeaderFieldName(request.Method) || request.Headers == nil ||
		(credentials != CredentialsInclude && credentials != CredentialsOmit) {
		return TargetRequest{}, invalid
	}
	for name, value := range request.Headers {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return TargetRequest{}, invalid
		}
	}
	var body []byte
	if request.Body != nil {
		body, err = base64.StdEncoding.Strict().DecodeString(*request.Body)
		if err != nil || base64.StdEncoding.EncodeToString(body) != *request.Body {
			return TargetRequest{}, invalid
		}
		if body == nil {
			body = []byte{}
		}
	}
	return TargetRequest{
		Role: request.Role, URL: request.URL, Method: request.Method,
		Headers: request.Headers, Body: body, Credentials: credentials,
	}, nil
}
