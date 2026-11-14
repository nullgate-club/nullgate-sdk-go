package threatmetrix

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/profilewire"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/turn"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http/httpguts"
	"regexp"
)

type profileOperation struct {
	kind     string
	cancel   context.CancelFunc
	released bool
}

func (p *Profile) readMessages() error {
	operations := make(map[int64]*profileOperation)
	hello, ready, collected := false, false, false
	for {
		kind, data, err := p.conn.ReadMessage()
		if err != nil {
			if p.ctx.Err() != nil {
				return p.Err()
			}
			return &api.Error{Code: "transport_error", Message: "Profile connection failed", RequestID: p.RequestID, Cause: err}
		}
		if kind != websocket.TextMessage {
			return p.protocolError("expected a JSON text message")
		}
		var envelope profilewire.Command
		if err := json.Unmarshal(data, &envelope); err != nil || envelope.Type == "" {
			return p.protocolError("malformed JSON message")
		}
		if !hello && envelope.Type != "hello" && envelope.Type != "error" {
			return p.protocolError("expected hello before source work")
		}
		switch envelope.Type {
		case "hello":
			var message profilewire.Hello
			if profilewire.Decode(data, &message) != nil || hello ||
				message.Session == "" || !httpguts.ValidHeaderFieldValue(message.Session) {
				return p.protocolError("malformed or duplicate hello")
			}
			if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(message.RequestID) {
				return p.protocolError("hello has an invalid request ID")
			}
			p.mu.Lock()
			p.RequestID = message.RequestID
			p.mu.Unlock()
			p.session.mu.Lock()
			p.session.state = message.Session
			p.session.mu.Unlock()
			hello = true
		case "http":
			var message profilewire.HTTP
			if profilewire.Decode(data, &message) != nil || message.ID == nil || *message.ID < 1 || *message.ID > 9007199254740991 || message.Request == nil {
				return p.protocolError("malformed HTTP request")
			}
			var frame struct {
				Request map[string]json.RawMessage `json:"request"`
			}
			if json.Unmarshal(data, &frame) != nil || frame.Request["body"] == nil {
				return p.protocolError("malformed target HTTP request")
			}
			if _, exists := operations[*message.ID]; exists {
				return p.protocolError("duplicate network correlation ID")
			}
			request, err := targetRequest(message.Request)
			if err != nil {
				return p.protocolError("malformed target HTTP request")
			}
			operations[*message.ID] = &profileOperation{kind: "http"}
			p.workers.Add(1)
			go p.serveHTTP(*message.ID, request)
		case "ice":
			var message profilewire.ICE
			if profilewire.Decode(data, &message) != nil || message.ID == nil || *message.ID < 1 || *message.ID > 9007199254740991 || message.Server == nil ||
				message.Server.Host == "" || strings.ContainsAny(message.Server.Host, "\r\n\t /\\?#@[]") ||
				message.Server.Port < 1 || message.Server.Port > 65535 || message.Server.Transport != "tcp" {
				return p.protocolError("malformed TURN/TCP request")
			}
			if _, exists := operations[*message.ID]; exists {
				return p.protocolError("duplicate network correlation ID")
			}
			ctx, cancel := context.WithCancel(p.ctx)
			operations[*message.ID] = &profileOperation{kind: "ice", cancel: cancel}
			p.workers.Add(1)
			go p.serveICE(ctx, *message.ID, *message.Server)
		case "ice.release":
			var message profilewire.ICERelease
			if profilewire.Decode(data, &message) != nil || message.ID == nil {
				return p.protocolError("malformed ICE release")
			}
			operation := operations[*message.ID]
			if operation == nil || operation.kind != "ice" || operation.released {
				return p.protocolError("unknown or duplicate ICE release correlation ID")
			}
			operation.released = true
			operation.cancel()
		case "ready", "collected":
			var message profilewire.Notice
			if profilewire.Decode(data, &message) != nil || message.RequestID != p.RequestID {
				return p.protocolError("invalid source completion request ID")
			}
			if envelope.Type == "ready" {
				if ready {
					return p.protocolError("duplicate ready")
				}
				ready = true
				close(p.ready)
			} else {
				if !ready || collected {
					return p.protocolError("premature or duplicate collected")
				}
				collected = true
				close(p.collected)
			}
		case "pagehide.done":
			var message profilewire.Command
			if profilewire.Decode(data, &message) != nil {
				return p.protocolError("malformed pagehide acknowledgment")
			}
			p.mu.Lock()
			ack := p.pageDone
			p.pageDone = nil
			p.mu.Unlock()
			if ack == nil {
				return p.protocolError("unsolicited pagehide acknowledgment")
			}
			close(ack)
		case "error":
			var message profilewire.ServiceError
			if profilewire.Decode(data, &message) != nil || message.Code == "" || message.Message == "" || message.RequestID == "" {
				return p.protocolError("malformed service error")
			}
			return &api.Error{Code: message.Code, Message: message.Message, RequestID: message.RequestID}
		default:
			return p.protocolError("unknown message kind")
		}
	}
}

func (p *Profile) serveHTTP(id int64, request TargetRequest) {
	defer p.workers.Done()
	response, err := p.target.fetch(p.ctx, request)
	receivedAt := time.Now().UnixMilli()
	if p.ctx.Err() != nil {
		return
	}
	if err != nil {
		_ = p.send(p.ctx, profilewire.HTTPError{Type: "http.error", ID: id, Detail: "Target request failed"})
		return
	}
	if response.Status < 100 || response.Status > 599 {
		p.stop(p.protocolError("target fetch returned an invalid response"))
		return
	}
	for name, value := range response.Headers {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			p.stop(p.protocolError("target fetch returned invalid headers"))
			return
		}
	}
	if response.Headers == nil {
		response.Headers = map[string]string{}
	}
	if response.Body == nil {
		response.Body = []byte{}
	}
	_ = p.send(p.ctx, profilewire.HTTPResult{Type: "http.result", ID: id, Response: profilewire.HTTPResponse{
		Status: response.Status, Headers: response.Headers, Body: response.Body, ReceivedAtMS: receivedAt,
	}})
}

func (p *Profile) serveICE(ctx context.Context, id int64, server turn.Server) {
	defer p.workers.Done()
	if err := turn.Observe(ctx, p.target.dial, server, func(observation *turn.Observation) error {
		return p.send(p.ctx, profilewire.ICEResult{
			Type: "ice.result", ID: id, Observation: observation,
		})
	}); err != nil && ctx.Err() == nil {
		p.stop(&api.Error{Code: "transport_error", Message: "TURN connection failed", Cause: err})
	}
}
