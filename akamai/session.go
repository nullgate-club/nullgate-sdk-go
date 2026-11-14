package akamai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/protocol"
)

func failure(code, message string) *api.Error { return &api.Error{Code: code, Message: message} }
func protocolError(message string) *api.Error { return failure("protocol_error", message) }

type Client struct{ connection *api.Client }

func New(connection *api.Client) *Client { return &Client{connection: connection} }

type Session struct {
	connection *api.Client
	visit      *browser.Session
	state      string
	gate       chan struct{}
	retained   *sensorRetention
}
type sensorRetention struct {
	page            *browser.Page
	session, digest string
}

func (c *Client) Session(visit *browser.Session) (*Session, error) {
	if c.connection.Closed() {
		return nil, api.ErrClosed
	}
	if visit == nil {
		return nil, failure("invalid_request", "browser session must not be nil")
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Session{connection: c.connection, visit: visit, gate: gate}, nil
}
func (s *Session) validate(ctx context.Context, page *browser.Page) error {
	if ctx == nil {
		return failure("invalid_request", "Context must not be nil")
	}
	if page == nil || page.Session() != s.visit {
		return failure("invalid_request", "page belongs to a different browser session")
	}
	return nil
}
func (s *Session) generate(ctx context.Context, p *browser.Page, operation string, fields map[string]any, script string) (*Request, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
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
	body := protocol.Context(p, s.state)
	for k, v := range fields {
		body[k] = v
	}
	sensor := operation == "sensor"
	digest := ""
	if sensor {
		sum := sha256.Sum256([]byte(script))
		digest = hex.EncodeToString(sum[:])
		if retained := s.retained; retained != nil && retained.page == p && retained.session == body["session"] && retained.digest == digest {
			delete(body, "script")
			body["script_digest"] = digest
		}
		s.retained = nil
	}
	var data map[string]any
	if err := s.connection.Call(ctx, "/akamai/"+operation, body, &data, script, true); err != nil {
		return nil, err
	}
	result, err := decodeRequest(data, p.URL(), s.connection)
	if err != nil {
		return nil, err
	}
	state, ok := data["session"].(string)
	if !ok || state == "" {
		return nil, protocolError("Missing response session")
	}
	s.state = state
	if sensor {
		if retained, _ := data["script_retained"].(bool); retained {
			s.retained = &sensorRetention{page: p, session: state, digest: digest}
		}
	} else if operation == "pixel" || s.retained != nil && (s.retained.page != p || s.retained.session != state) {
		s.retained = nil
	}
	return result, nil
}
