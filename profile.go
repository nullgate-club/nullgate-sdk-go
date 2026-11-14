package nullgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/profilewire"
)

// Profile owns one active document connection. Ready startup is not collector
// completion or target acceptance. Keep the context passed to Page.ThreatMetrix
// alive until departure/Close, and do not copy a Profile after first use.
type Profile struct {
	RequestID string

	session   *Session
	target    target
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

// Collector identifies a known ThreatMetrix collector.
type Collector struct {
	URL, OrgID, SessionID string
}

// ThreatMetrixOptions supplies the target transport and observed page data.
type ThreatMetrixOptions struct {
	Send      TargetFetch
	ScriptURL string
	Collector *Collector
	Proxy     string
	Inputs    []PreparedInput
	Actions   []Action
}

// ThreatMetrix starts profiling and returns once the document is ready.
func (page *Page) ThreatMetrix(ctx context.Context, opts ThreatMetrixOptions) (*Profile, error) {
	if ctx == nil {
		return nil, errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := newTarget(opts.Send, opts.Proxy)
	if err != nil {
		return nil, err
	}
	release, err := page.session.acquire(ctx, "threatmetrix")
	if err != nil {
		return nil, err
	}
	defer release()
	start := page.session.context("threatmetrix", page)
	start["type"] = "start"
	start["at_ms"] = time.Now().UnixMilli()
	if opts.Collector != nil {
		if opts.ScriptURL != "" {
			return nil, newError("invalid_request", "provide either a script URL or collector")
		}
		c := opts.Collector
		u, err := absoluteHTTPURL(c.URL)
		if err != nil || u.User != nil || strings.ContainsAny(c.URL, "#\\") || strings.IndexFunc(c.URL, unicode.IsSpace) >= 0 || c.OrgID == "" || c.SessionID == "" {
			return nil, newError("invalid_request", "invalid collector")
		}
		start["collector"] = profilewire.Collector{URL: c.URL, OrgID: c.OrgID, SessionID: c.SessionID}
	} else {
		script, err := page.script("profile", opts.ScriptURL)
		if err != nil {
			return nil, err
		}
		start["tags_url"] = script
	}
	if opts.Inputs != nil {
		inputs, err := page.prepareInputs(opts.Inputs)
		if err != nil {
			return nil, err
		}
		start["inputs"] = inputs
	}
	if err := validateActions(opts.Actions); err != nil {
		return nil, err
	}
	if opts.Actions != nil {
		start["actions"] = opts.Actions
	}
	data, err := json.Marshal(start)
	if err != nil {
		return nil, protocolError("start payload could not be encoded")
	}
	profileCtx, cancel := context.WithCancel(ctx)
	p := &Profile{session: page.session, target: target, ctx: profileCtx, cancel: cancel,
		ready: make(chan struct{}), collected: make(chan struct{}), done: make(chan struct{}),
		writeGate: make(chan struct{}, 1), pageGate: make(chan struct{}, 1)}
	client := page.session.client
	client.profilesMu.Lock()
	if client.api.Closed() {
		client.profilesMu.Unlock()
		cancel()
		return nil, ErrClosed
	}
	if client.profiles == nil {
		client.profiles = make(map[*Profile]struct{})
	}
	client.profiles[p] = struct{}{}
	client.profilesMu.Unlock()
	go p.run(data)
	timer := time.NewTimer(client.api.Timeout)
	defer timer.Stop()
	select {
	case <-p.ready:
		if err := p.Err(); err != nil {
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
	case <-timer.C:
		err := newError("timeout", "Profile startup timed out")
		p.stop(err)
		<-p.done
		return nil, err
	}
}

func (p *Profile) run(start []byte) {
	defer func() {
		if err := p.ctx.Err(); err != nil {
			p.stop(err)
		} else {
			p.stop(ErrClosed)
		}
		p.workers.Wait()
		p.mu.Lock()
		p.conn, p.target, p.pageDone = nil, target{}, nil
		p.mu.Unlock()
		p.session.client.profilesMu.Lock()
		delete(p.session.client.profiles, p)
		p.session.client.profilesMu.Unlock()
		close(p.done)
	}()
	stopContext := context.AfterFunc(p.ctx, func() { p.stop(p.ctx.Err()) })
	defer stopContext()
	if p.ctx.Err() != nil {
		p.stop(p.ctx.Err())
		return
	}
	client := p.session.client
	endpoint := strings.Replace(client.api.BaseURL, "https://", "wss://", 1)
	endpoint = strings.Replace(endpoint, "http://", "ws://", 1)
	endpoint += "/threatmetrix/profile"
	dialer := websocket.Dialer{HandshakeTimeout: client.api.Timeout}
	// API WebSockets never adopt HTTP(S)_PROXY. Only an explicitly supplied API
	// transport's dial/TLS settings are reused, not its proxy or cookie settings.
	if transport, ok := client.api.HTTP.Transport.(*http.Transport); ok {
		dialer.NetDialContext = transport.DialContext
		if transport.TLSClientConfig != nil {
			dialer.TLSClientConfig = transport.TLSClientConfig.Clone()
			// Gorilla upgrades over HTTP/1.1, even after API HTTP negotiated h2.
			dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+client.api.Key)
	var conn *websocket.Conn
	var response *http.Response
	var err error
	for attempt := 0; ; attempt++ {
		conn, response, err = dialer.DialContext(p.ctx, endpoint, headers)
		if err == nil || response == nil || response.Body == nil {
			break
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		var failure Error
		valid := readErr == nil && json.Unmarshal(body, &failure) == nil && failure.Code != "" && failure.Message != "" && failure.RequestID != ""
		delay, retry := profileRetryDelay(response.Header.Get("Retry-After"))
		if valid && failure.Code == "maintenance" && retry && attempt < 2 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
				continue
			case <-p.ctx.Done():
				timer.Stop()
				p.stop(p.ctx.Err())
				return
			}
		}
		if !valid {
			failure = *protocolError("Profile handshake rejected")
		}
		failure.Status = response.StatusCode
		p.stop(&failure)
		return
	}
	if err != nil {
		if p.ctx.Err() != nil {
			p.stop(p.ctx.Err())
		} else if response != nil && response.StatusCode >= 400 {
			failure := protocolError("Profile handshake rejected")
			failure.Status = response.StatusCode
			p.stop(failure)
		} else {
			p.stop(&Error{Code: "transport_error", Message: "Profile connection failed", Cause: err})
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
func profileRetryDelay(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 && seconds <= 86400 {
		return time.Duration(seconds * float64(time.Second)), true
	}
	if at, err := http.ParseTime(value); err == nil {
		delay := time.Until(at)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
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
	if err := p.Err(); err != nil {
		return err
	}
	select {
	case <-p.collected:
		return p.Err()
	default:
	}
	select {
	case <-p.collected:
		return p.Err()
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
	if at < 0 {
		return newError("invalid_request", "pagehide time must be nonnegative")
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
			if errors.Is(err, ErrClosed) {
				_ = conn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
					time.Now().Add(time.Second),
				)
			}
			conn.Close()
		}
	})
}

func (p *Profile) protocolError(problem string) *Error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return &Error{Code: "protocol_error", Message: problem, RequestID: p.RequestID}
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
		failure := &Error{Code: "transport_error", Message: "Profile connection failed", RequestID: requestID, Cause: err}
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
		failure := &Error{Code: "transport_error", Message: "Profile connection failed", RequestID: requestID, Cause: err}
		p.stop(failure)
		return failure
	}
	return nil
}
