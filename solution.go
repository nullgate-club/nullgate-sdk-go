package nullgate

import (
	"context"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Request contains a target request. Send it through your own HTTP client after Wait.
// Headers preserve server casing. Standard net/http does not preserve HTTP header wire order.
type Request struct {
	URL       string
	Body      []byte
	Headers   map[string]string
	SendAt    float64
	RequestID string
	client    *Client
}

func (*Request) String() string                             { return "nullgate.Request{Body:<redacted>,Headers:<redacted>}" }
func (r *Request) GoString() string                         { return r.String() }
func (r *Request) Wait(ctx context.Context) error           { return waitUntil(ctx, r.SendAt) }
func (r *Request) Report(ctx context.Context) (bool, error) { return r.client.Report(ctx, r.RequestID) }

// FwcimResult contains metadata1 for the original sign-in form.
type FwcimResult struct {
	Metadata1 string
	Headers   map[string]string
	SendAt    float64
	RequestID string
	client    *Client
}

func (*FwcimResult) String() string                   { return "nullgate.FwcimResult{Metadata1:<redacted>}" }
func (r *FwcimResult) GoString() string               { return r.String() }
func (r *FwcimResult) Wait(ctx context.Context) error { return waitUntil(ctx, r.SendAt) }
func (r *FwcimResult) Report(ctx context.Context) (bool, error) {
	return r.client.Report(ctx, r.RequestID)
}

func waitUntil(ctx context.Context, sendAt float64) error {
	if ctx == nil {
		return newError("invalid_request", "Context must not be nil")
	}
	if math.IsNaN(sendAt) || math.IsInf(sendAt, 0) {
		return protocolError("Invalid send_at")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := sendAt - float64(time.Now().UnixNano())/1e9
		if remaining <= 0 {
			return nil
		}
		// Avoid overflowing time.Duration for an arbitrary server timestamp.
		interval := time.Duration(math.Min(remaining, 3600) * float64(time.Second))
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func resultHeaders(value any) (map[string]string, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, protocolError("Missing response headers")
	}
	headers := make(map[string]string, len(fields))
	for key, value := range fields {
		text, ok := value.(string)
		if !ok || !headerName.MatchString(key) || strings.ContainsAny(text, "\r\n\x00") {
			return nil, protocolError("Invalid response headers")
		}
		headers[key] = text
	}
	return headers, nil
}
func resultTiming(data map[string]any) (float64, error) {
	value, ok := data["send_at"].(float64)
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, protocolError("Missing or invalid send_at")
	}
	return value, nil
}
func decodeRequest(data map[string]any, pageURL string, c *Client) (*Request, error) {
	value, ok := data["request"].(map[string]any)
	if !ok {
		return nil, protocolError("Missing generated request")
	}
	id, ok := data["request_id"].(string)
	if !ok || id == "" {
		return nil, protocolError("Missing request_id")
	}
	address, ok := value["url"].(string)
	if !ok {
		return nil, protocolError("Missing request URL")
	}
	if _, err := absoluteHTTPURL(address); err != nil {
		return nil, protocolError("Invalid request URL")
	}
	body, ok := value["body"].(string)
	if !ok {
		return nil, protocolError("Missing request body")
	}
	headers, err := resultHeaders(value["headers"])
	if err != nil {
		return nil, err
	}
	sendAt, err := resultTiming(value)
	if err != nil {
		return nil, err
	}
	page, err := url.Parse(pageURL)
	if err != nil {
		return nil, protocolError("Invalid page URL")
	}
	headers["origin"] = page.Scheme + "://" + page.Host
	headers["referer"] = pageURL
	return &Request{URL: address, Body: []byte(body), Headers: headers, SendAt: sendAt, RequestID: id, client: c}, nil
}
func decodeFwcim(data map[string]any, c *Client) (*FwcimResult, error) {
	id, ok := data["request_id"].(string)
	if !ok || id == "" {
		return nil, protocolError("Missing request_id")
	}
	metadata, ok := data["metadata1"].(string)
	if !ok || metadata == "" {
		return nil, protocolError("Missing metadata1")
	}
	headers, err := resultHeaders(data["headers"])
	if err != nil {
		return nil, err
	}
	sendAt, err := resultTiming(data)
	if err != nil {
		return nil, err
	}
	return &FwcimResult{Metadata1: metadata, Headers: headers, SendAt: sendAt, RequestID: id, client: c}, nil
}
