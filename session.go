package nullgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// SessionOptions identifies a browser profile and its environment.
type SessionOptions struct {
	UserAgent string
	Profile   string
	Timezone  *string
}

// Session tracks independent continuation states for each product.
type Session struct {
	client             *Client
	userAgent, profile string
	timezone           *string
	mu                 sync.Mutex
	states             map[string]string
	gates              map[string]chan struct{}
	retained           *sensorRetention
}

type sensorRetention struct {
	page            *Page
	session, digest string
}

// Session creates a local session without contacting the API.
func (c *Client) Session(opts SessionOptions) (*Session, error) {
	if c.api.Closed() {
		return nil, ErrClosed
	}
	if strings.TrimSpace(opts.UserAgent) == "" || strings.ContainsAny(opts.UserAgent, "\r\n") {
		return nil, newError("invalid_request", "user agent must be a nonempty header value")
	}
	profile := opts.Profile
	if profile == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		profile = id.String()
	} else {
		id, err := uuid.Parse(profile)
		if err != nil {
			return nil, newError("invalid_request", "profile must be a UUID")
		}
		profile = id.String()
	}
	var timezone *string
	if opts.Timezone != nil {
		value := *opts.Timezone
		timezone = &value
	}
	return &Session{client: c, userAgent: opts.UserAgent, profile: profile, timezone: timezone, states: make(map[string]string), gates: make(map[string]chan struct{})}, nil
}

func (s *Session) acquire(ctx context.Context, product string) (func(), error) {
	if ctx == nil {
		return nil, newError("invalid_request", "Context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	gate := s.gates[product]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		s.gates[product] = gate
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.client.api.Done():
		return nil, ErrClosed
	case <-gate:
		if s.client.api.Closed() {
			gate <- struct{}{}
			return nil, ErrClosed
		}
		return func() { gate <- struct{}{} }, nil
	}
}

func (s *Session) context(product string, p *Page) map[string]any {
	s.mu.Lock()
	state := s.states[product]
	s.mu.Unlock()
	var current any
	if state != "" {
		current = state
	}
	body := map[string]any{"profile": s.profile, "session": current, "user_agent": s.userAgent, "url": p.url, "html": p.html, "document_id": p.documentID, "started_at_ms": p.startedAtMS}
	if s.timezone != nil {
		body["timezone"] = *s.timezone
	}
	return body
}

func (s *Session) rotate(product, state string) {
	s.mu.Lock()
	s.states[product] = state
	s.mu.Unlock()
}

func (s *Session) run(ctx context.Context, product, operation string, p *Page, fields map[string]any, script string, finish func(map[string]any) error) error {
	release, err := s.acquire(ctx, product)
	if err != nil {
		return err
	}
	defer release()
	body := s.context(product, p)
	for k, v := range fields {
		body[k] = v
	}
	sensor := product == "akamai" && operation == "sensor"
	digest := ""
	if sensor {
		sum := sha256.Sum256([]byte(script))
		digest = hex.EncodeToString(sum[:])
		s.mu.Lock()
		if r := s.retained; r != nil && r.page == p && r.session == body["session"] && r.digest == digest {
			delete(body, "script")
			body["script_digest"] = digest
		}
		s.retained = nil
		s.mu.Unlock()
	}
	var data map[string]any
	if err := s.client.call(ctx, "/"+product+"/"+operation, body, &data, script, true); err != nil {
		return err
	}
	if err := finish(data); err != nil {
		return err
	}
	state, ok := data["session"].(string)
	if !ok || state == "" {
		return protocolError("Missing response session")
	}
	s.mu.Lock()
	s.states[product] = state
	if sensor {
		if retained, _ := data["script_retained"].(bool); retained {
			s.retained = &sensorRetention{page: p, session: state, digest: digest}
		}
	} else if product == "akamai" && (operation == "pixel" || s.retained != nil && (s.retained.page != p || s.retained.session != state)) {
		s.retained = nil
	}
	s.mu.Unlock()
	return nil
}
