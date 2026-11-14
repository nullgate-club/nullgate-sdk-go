package akamai

import (
	"context"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/protocol"
	"net/url"
)

// Request contains a target request. Send it through your own HTTP client after Wait.
// Headers preserve server casing. Standard net/http does not preserve HTTP header wire order.
type Request struct {
	URL       string
	Body      []byte
	Headers   map[string]string
	SendAt    float64
	RequestID string
	client    *api.Client
}

func (*Request) String() string                             { return "nullgate.Request{Body:<redacted>,Headers:<redacted>}" }
func (r *Request) GoString() string                         { return r.String() }
func (r *Request) Wait(ctx context.Context) error           { return protocol.Wait(ctx, r.SendAt) }
func (r *Request) Report(ctx context.Context) (bool, error) { return r.client.Report(ctx, r.RequestID) }

func decodeRequest(data map[string]any, pageURL string, c *api.Client) (*Request, error) {
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
	if _, err := api.AbsoluteHTTPURL(address); err != nil {
		return nil, protocolError("Invalid request URL")
	}
	body, ok := value["body"].(string)
	if !ok {
		return nil, protocolError("Missing request body")
	}
	headers, err := protocol.Headers(value["headers"])
	if err != nil {
		return nil, err
	}
	sendAt, err := protocol.Timing(value)
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
