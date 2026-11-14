// Package nullgate assembles product clients sharing one authenticated API connection.
// Target requests remain caller-owned. See each product package for its operations.
package nullgate

import (
	"context"

	"github.com/nullgate-club/nullgate-sdk-go/v2/accounts"
	"github.com/nullgate-club/nullgate-sdk-go/v2/akamai"
	"github.com/nullgate-club/nullgate-sdk-go/v2/amazon"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/classifier"
	"github.com/nullgate-club/nullgate-sdk-go/v2/threatmetrix"
)

// Client shares API configuration and cancellation across its product clients.
type Client struct {
	Accounts     *accounts.Client
	Akamai       *akamai.Client
	Amazon       *amazon.Client
	ThreatMetrix *threatmetrix.Client
	Classifier   *classifier.Client
	connection   *api.Client
}

func (*Client) String() string     { return "nullgate.Client{APIKey:<redacted>}" }
func (c *Client) GoString() string { return c.String() }

// New validates configuration without network I/O. An empty key reads NULLGATE_API_KEY.
func New(key string, options api.Options) (*Client, error) {
	connection, err := api.New(key, options)
	if err != nil {
		return nil, err
	}
	return &Client{
		Accounts: accounts.New(connection), Akamai: akamai.New(connection),
		Amazon: amazon.New(connection), ThreatMetrix: threatmetrix.New(connection),
		Classifier: classifier.New(connection), connection: connection,
	}, nil
}

// Close cancels API requests and closes active profiles and SDK-owned connections.
func (c *Client) Close() error {
	_ = c.connection.Close()
	return c.ThreatMetrix.Close()
}

// Report records a request ID. True means HTTP delivery, not acceptance or a refund.
func (c *Client) Report(ctx context.Context, requestID string) (bool, error) {
	return c.connection.Report(ctx, requestID)
}
