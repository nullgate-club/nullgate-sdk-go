package nullgate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/internal/profilewire"
)

// Profile owns one active document connection. Ready startup is not collector
// completion or target acceptance. Keep the context passed to Session.Profile
// alive until departure/Close, and do not copy a Profile after first use.
type Profile struct {
	RequestID string

	session   *Session
	target    Target
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	collected chan struct{}
	done      chan struct{}
	writeGate chan struct{}
	pageGate  chan struct{}
	workers   sync.WaitGroup
	stopOnce  sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	conn      *websocket.Conn
	err       error
	pageDone  chan struct{}
}

func (*Profile) String() string     { return "nullgate.Profile{Document:<redacted>, State:<redacted>}" }
func (p *Profile) GoString() string { return p.String() }

// Profile begins a ThreatMetrix document using the session's identity, user
// agent, timezone and continuation state. It serializes startup with Solve and
// other profile starts, then returns at ready while one background reader keeps
// servicing HTTP and ICE. There is no reconnect or paid-profile retry.
func (s *Session) Profile(ctx context.Context, params ThreatMetrixParams, target Target) (*Profile, error) {
	if ctx == nil {
		return nil, errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target.fetch == nil || target.dial == nil {
		return nil, errors.New("nullgate: Target must be constructed with NewTarget")
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	previous := s.document
	closed := s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return nil, ErrClosed
	}
	website, err := observePage(params.Protection.Page, previous)
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(website.URL)
	reference, err := url.Parse(params.Protection.TagsURL)
	if err != nil {
		return nil, errors.New("nullgate: ThreatMetrix.TagsURL must be a tags.js URL with one nonempty org_id and session_id")
	}
	tags := base.ResolveReference(reference)
	tags.Fragment, tags.RawFragment = "", ""
	if !isThreatMetrixTags(tags) {
		return nil, errors.New("nullgate: ThreatMetrix.TagsURL must be a tags.js URL with one nonempty org_id and session_id")
	}
	var inputs *[]PreparedInput
	if params.Inputs != nil {
		prepared := PrepareInputs(params.Inputs)
		inputs = &prepared
	}
	if err := validateActions(params.Actions); err != nil {
		return nil, err
	}
	var actions *[]Action
	if params.Actions != nil {
		actions = &params.Actions
	}
	start, err := json.Marshal(profileStart{
		Type: "start", Website: website, TagsURL: tags.String(), Timezone: s.timezone,
		AtMS:   time.Now().UnixMilli(),
		Inputs: inputs, Actions: actions,
	})
	if err != nil {
		return nil, &ProtocolError{Problem: "start payload could not be JSON encoded", Operation: "profile"}
	}
	profileCtx, cancel := context.WithCancel(ctx)
	p := &Profile{
		session: s, target: target, ctx: profileCtx, cancel: cancel,
		ready: make(chan struct{}), collected: make(chan struct{}), done: make(chan struct{}),
		writeGate: make(chan struct{}, 1), pageGate: make(chan struct{}, 1),
	}
	// Register before connecting so owner Close also cancels a pending handshake.
	s.client.profilesMu.Lock()
	s.mu.Lock()
	if s.closed || s.client.closed.Load() {
		s.mu.Unlock()
		s.client.profilesMu.Unlock()
		cancel()
		return nil, ErrClosed
	}
	stateID := s.stateID
	s.document = website
	if s.profiles == nil {
		s.profiles = make(map[*Profile]struct{})
	}
	if s.client.profiles == nil {
		s.client.profiles = make(map[*Profile]struct{})
	}
	s.profiles[p] = struct{}{}
	s.client.profiles[p] = struct{}{}
	s.mu.Unlock()
	s.client.profilesMu.Unlock()
	go p.run(stateID, start)
	select {
	case <-p.ready:
		if err := p.Err(); err != nil {
			<-p.done
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			p.stop(err)
			<-p.done
			return nil, err
		}
		return p, nil
	case <-p.done:
		return nil, p.Err()
	case <-ctx.Done():
		p.stop(ctx.Err())
		<-p.done
		return nil, ctx.Err()
	}
}

func (p *Profile) run(stateID string, start []byte) {
	defer func() {
		p.stop(ErrClosed)
		p.workers.Wait()
		p.mu.Lock()
		p.conn, p.target, p.pageDone = nil, Target{}, nil
		p.mu.Unlock()
		p.session.client.profilesMu.Lock()
		delete(p.session.client.profiles, p)
		p.session.client.profilesMu.Unlock()
		p.session.mu.Lock()
		delete(p.session.profiles, p)
		p.session.mu.Unlock()
		close(p.done)
	}()
	stopContext := context.AfterFunc(p.ctx, func() { p.stop(p.ctx.Err()) })
	defer stopContext()
	if p.ctx.Err() != nil {
		p.stop(p.ctx.Err())
		return
	}
	client := p.session.client
	endpoint := strings.Replace(client.profileBaseURL, "https://", "wss://", 1)
	endpoint = strings.Replace(endpoint, "http://", "ws://", 1)
	endpoint += "/v1/" + p.session.identity + "/profile"
	dialer := websocket.Dialer{HandshakeTimeout: client.http.Timeout}
	// API WebSockets never adopt HTTP(S)_PROXY. Only an explicitly supplied API
	// transport's dial/TLS settings are reused, not its proxy or cookie settings.
	if transport, ok := client.http.Transport.(*http.Transport); ok {
		dialer.NetDialContext = transport.DialContext
		if transport.TLSClientConfig != nil {
			dialer.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+client.apiKey)
	headers.Set("User-Agent", p.session.userAgent)
	headers.Set("X-State-ID", stateID)
	conn, response, err := dialer.DialContext(p.ctx, endpoint, headers)
	if err != nil {
		if p.ctx.Err() != nil {
			p.stop(p.ctx.Err())
		} else if response != nil && response.StatusCode >= 400 {
			requestID := response.Header.Get("X-Request-ID")
			if _, err := uuid.Parse(requestID); err != nil {
				requestID = ""
			}
			p.stop(&APIError{StatusCode: response.StatusCode, RequestID: requestID})
		} else {
			p.stop(&TransportError{Operation: "profile", Err: err})
		}
		return
	}
	p.mu.Lock()
	p.conn = conn
	stopped := p.err != nil
	p.mu.Unlock()
	if stopped {
		conn.Close()
		return
	}
	if err := p.send(p.ctx, start); err != nil {
		return
	}
	p.stop(p.readMessages())
}

// Done closes only after the connection and all owned network work have stopped.
// Collected is separate; WaitCollected observes actual source completion.
func (p *Profile) Done() <-chan struct{} { return p.done }

// Err returns the terminal service, protocol, transport or cancellation error.
// An active profile has nil Err. Explicit Close is not collector completion.
func (p *Profile) Err() error {
	p.mu.Lock()
	err := p.err
	p.mu.Unlock()
	if err != nil {
		return err
	}
	// Context cancellation is visible before its cleanup callback is scheduled.
	return p.ctx.Err()
}

// WaitCollected waits for all installed source lifetimes, not just ready. It
// neither invents page departure nor closes the socket when collection finishes.
func (p *Profile) WaitCollected(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-p.collected:
		return nil
	default:
	}
	select {
	case <-p.collected:
		return nil
	case <-p.ctx.Done():
		return p.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pagehide explicitly delivers departure, using the caller's wall clock when
// atMS is nil. It waits for pagehide.done while the reader still serves network
// work. Persisted departure does not close the Profile. Canceling ctx after the
// request is sent closes the Profile, since acknowledgments have no request ID.
func (p *Profile) Pagehide(ctx context.Context, atMS *int64, persisted bool) error {
	if ctx == nil {
		return errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.pageGate <- struct{}{}:
		defer func() { <-p.pageGate }()
	case <-p.ctx.Done():
		return p.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	at := time.Now().UnixMilli()
	if atMS != nil {
		at = *atMS
	}
	ack := make(chan struct{})
	p.mu.Lock()
	if p.err != nil {
		err := p.err
		p.mu.Unlock()
		return err
	}
	p.pageDone = ack
	p.mu.Unlock()
	stopContext := context.AfterFunc(ctx, func() { p.stop(ctx.Err()) })
	defer stopContext()
	if err := p.send(ctx, profilewire.Pagehide{Type: "pagehide", AtMS: at, Persisted: persisted}); err != nil {
		return err
	}
	select {
	case <-ack:
		return nil
	case <-p.ctx.Done():
		return p.Err()
	case <-ctx.Done():
		p.stop(ctx.Err())
		return ctx.Err()
	}
}

// Close cancels profiling without generating pagehide. It waits for owned HTTP,
// TURN allocations/streams and the reader to stop. TargetFetch must honor its
// context; Close cannot forcibly terminate a caller callback that ignores it.
func (p *Profile) Close() error {
	p.closeOnce.Do(func() {
		if p.Err() == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = p.send(ctx, profilewire.Command{Type: "close"})
			cancel()
		}
		p.stop(ErrClosed)
	})
	<-p.done
	return nil
}

// Report preserves Client.Report's anonymous analytics delivery semantics.
func (p *Profile) Report(ctx context.Context) (bool, error) {
	return p.session.client.Report(ctx, p.RequestID)
}

func (p *Profile) stop(err error) {
	p.stopOnce.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		p.mu.Lock()
		p.err = err
		conn := p.conn
		p.mu.Unlock()
		p.cancel()
		if conn != nil {
			conn.Close()
		}
	})
}

func (p *Profile) protocolError(problem string) *ProtocolError {
	p.mu.Lock()
	defer p.mu.Unlock()
	return &ProtocolError{Problem: problem, Operation: "profile", RequestID: p.RequestID}
}

func (p *Profile) send(ctx context.Context, message any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return p.Err()
	}
	defer func() { <-p.writeGate }()
	p.mu.Lock()
	conn, stopped, requestID := p.conn, p.err, p.RequestID
	p.mu.Unlock()
	if stopped != nil {
		return stopped
	}
	if conn == nil {
		return ErrClosed
	}
	deadline := time.Now().Add(10 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		failure := &TransportError{Operation: "profile", RequestID: requestID, Err: err}
		p.stop(failure)
		return failure
	}
	var err error
	if data, ok := message.([]byte); ok {
		err = conn.WriteMessage(websocket.TextMessage, data)
	} else {
		err = conn.WriteJSON(message)
	}
	if err != nil {
		if ctx.Err() != nil {
			p.stop(ctx.Err())
			return ctx.Err()
		}
		failure := &TransportError{Operation: "profile", RequestID: requestID, Err: err}
		p.stop(failure)
		return failure
	}
	return nil
}
