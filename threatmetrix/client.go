// Package threatmetrix manages profiling sessions and target network callbacks.
package threatmetrix

import (
	"context"
	"sync"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
)

// Client owns active profiles created through its sessions.
type Client struct {
	api      *api.Client
	mu       sync.Mutex
	closed   bool
	done     chan struct{}
	profiles map[*Profile]struct{}
}

// New creates a product client using the shared API connection.
func New(connection *api.Client) *Client {
	return &Client{api: connection, profiles: make(map[*Profile]struct{}), done: make(chan struct{})}
}

// Session binds ThreatMetrix continuation state to a browser visit.
func (c *Client) Session(visit *browser.Session) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.api.Closed() {
		return nil, api.ErrClosed
	}
	if visit == nil {
		return nil, newError("invalid_request", "browser session must not be nil")
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Session{client: c, visit: visit, gate: gate}, nil
}

// Close stops all active profiles and waits for their network work.
func (c *Client) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	active := make([]*Profile, 0, len(c.profiles))
	for p := range c.profiles {
		active = append(active, p)
	}
	c.mu.Unlock()
	for _, p := range active {
		_ = p.Close()
	}
	return nil
}

// Session serializes startup and retains the server continuation token.
type Session struct {
	client *Client
	visit  *browser.Session
	gate   chan struct{}
	mu     sync.Mutex
	state  string
}

func (s *Session) acquire(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.client.api.Done():
		return nil, api.ErrClosed
	case <-s.client.done:
		return nil, api.ErrClosed
	case <-s.gate:
		s.client.mu.Lock()
		closed := s.client.closed || s.client.api.Closed()
		s.client.mu.Unlock()
		if closed {
			s.gate <- struct{}{}
			return nil, api.ErrClosed
		}
		return func() { s.gate <- struct{}{} }, nil
	}
}

func newError(code, message string) *api.Error { return &api.Error{Code: code, Message: message} }
func protocolError(message string) *api.Error  { return newError("protocol_error", message) }
