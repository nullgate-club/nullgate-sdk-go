package amazon

import (
	"context"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/protocol"
)

// FwcimResult contains metadata1 for the original sign-in form.
type FwcimResult struct {
	Metadata1 string
	Headers   map[string]string
	SendAt    float64
	RequestID string
	client    *api.Client
}

func (*FwcimResult) String() string                   { return "nullgate.FwcimResult{Metadata1:<redacted>}" }
func (r *FwcimResult) GoString() string               { return r.String() }
func (r *FwcimResult) Wait(ctx context.Context) error { return protocol.Wait(ctx, r.SendAt) }
func (r *FwcimResult) Report(ctx context.Context) (bool, error) {
	return r.client.Report(ctx, r.RequestID)
}

func decodeFwcim(data map[string]any, c *api.Client) (*FwcimResult, error) {
	id, ok := data["request_id"].(string)
	if !ok || id == "" {
		return nil, api.ProtocolError("Missing request_id")
	}
	metadata, ok := data["metadata1"].(string)
	if !ok || metadata == "" {
		return nil, api.ProtocolError("Missing metadata1")
	}
	headers, err := protocol.Headers(data["headers"])
	if err != nil {
		return nil, err
	}
	sendAt, err := protocol.Timing(data)
	if err != nil {
		return nil, err
	}
	return &FwcimResult{Metadata1: metadata, Headers: headers, SendAt: sendAt, RequestID: id, client: c}, nil
}
