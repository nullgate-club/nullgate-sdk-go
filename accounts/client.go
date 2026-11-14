// Package accounts reads account balances, prices, and usage.
package accounts

import (
	"context"
	"net/url"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
)

type Client struct{ api *api.Client }

func New(connection *api.Client) *Client { return &Client{api: connection} }

// Monetary values are decimal strings, never rounded floating-point amounts.
type Account struct {
	ID            string            `json:"id"`
	Balance       string            `json:"balance"`
	Currency      string            `json:"currency"`
	CreatedAt     time.Time         `json:"created_at"`
	Active        bool              `json:"active"`
	PricesPer1000 map[string]string `json:"prices_per_1000"`
	Usage         []UsageTotal      `json:"usage"`
}
type UsageTotal struct {
	Operation string `json:"operation"`
	Requests  int64  `json:"requests"`
	Amount    string `json:"amount"`
}
type UsageOptions struct {
	Interval   string
	Start, End *time.Time
}
type UsageBucket struct {
	UsageTotal
	Start time.Time `json:"start"`
}
type Usage struct {
	Currency string        `json:"currency"`
	Interval string        `json:"interval"`
	Start    time.Time     `json:"start"`
	End      time.Time     `json:"end"`
	Buckets  []UsageBucket `json:"buckets"`
}

func (c *Client) Get(ctx context.Context) (*Account, error) {
	var result Account
	if err := c.api.Call(ctx, "/account", nil, &result, "", true); err != nil {
		return nil, err
	}
	if result.ID == "" || result.Balance == "" || result.CreatedAt.IsZero() || result.PricesPer1000 == nil || result.Usage == nil {
		return nil, api.ProtocolError("Malformed account response")
	}
	return &result, nil
}
func (c *Client) Usage(ctx context.Context, options UsageOptions) (*Usage, error) {
	interval := options.Interval
	if interval == "" {
		interval = "hour"
	}
	if interval != "hour" && interval != "day" {
		return nil, api.NewError("invalid_request", "Interval must be hour or day")
	}
	query := url.Values{"interval": {interval}}
	if options.Start != nil {
		query.Set("start", options.Start.UTC().Format(time.RFC3339Nano))
	}
	if options.End != nil {
		query.Set("end", options.End.UTC().Format(time.RFC3339Nano))
	}
	var result Usage
	if err := c.api.Call(ctx, "/account/usage?"+query.Encode(), nil, &result, "", true); err != nil {
		return nil, err
	}
	if result.Start.IsZero() || result.End.IsZero() || result.Buckets == nil || (result.Interval != "hour" && result.Interval != "day") {
		return nil, api.ProtocolError("Malformed usage response")
	}
	return &result, nil
}
