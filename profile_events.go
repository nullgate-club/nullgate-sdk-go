package nullgate

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/internal/profilewire"
	"github.com/nullgate-club/nullgate-sdk-go/internal/turn"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http/httpguts"
)

type profileStart struct {
	Type      string                 `json:"type"`
	AtMS      int64                  `json:"at_ms"`
	Website   websitePayload         `json:"website"`
	TagsURL   string                 `json:"tags_url,omitempty"`
	Collector *profilewire.Collector `json:"collector,omitempty"`
	Timezone  *string                `json:"timezone"`
	Inputs    *[]PreparedInput       `json:"inputs,omitempty"`
	Actions   *[]Action              `json:"actions,omitempty"`
}

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
			return &TransportError{Operation: "profile", RequestID: p.RequestID, Err: err}
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
				message.StateID == "" || !httpguts.ValidHeaderFieldValue(message.StateID) {
				return p.protocolError("malformed or duplicate hello")
			}
			if _, err := uuid.Parse(message.RequestID); err != nil {
				return p.protocolError("hello has an invalid request ID")
			}
			p.mu.Lock()
			p.RequestID = message.RequestID
			p.mu.Unlock()
			p.session.mu.Lock()
			if !p.session.closed {
				p.session.stateID = message.StateID
			}
			p.session.mu.Unlock()
			hello = true
		case "http":
			var message profilewire.HTTP
			if profilewire.Decode(data, &message) != nil || message.ID == nil || message.Request == nil {
				return p.protocolError("malformed HTTP request")
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
			if profilewire.Decode(data, &message) != nil || message.ID == nil || message.Server == nil ||
				message.Server.Host == "" || strings.ContainsAny(message.Server.Host, "\r\n\t /?#@[]") ||
				message.Server.Port < 1 || message.Server.Port > 65535 || message.Server.Transport != "tcp" ||
				message.Server.Username == "" || message.Server.Credential == "" {
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
			if profilewire.Decode(data, &message) != nil || message.Status < 400 || message.Status > 599 ||
				len(message.Detail) == 0 || (hello && message.RequestID != p.RequestID) {
				return p.protocolError("malformed service error")
			}
			if _, err := uuid.Parse(message.RequestID); err != nil {
				return p.protocolError("service error has an invalid request ID")
			}
			var detail any
			if err := json.Unmarshal(message.Detail, &detail); err != nil {
				return p.protocolError("malformed service error detail")
			}
			return &APIError{StatusCode: message.Status, Detail: detail, RequestID: message.RequestID}
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
	if err != nil || response.Status < 100 || response.Status > 999 {
		_ = p.send(p.ctx, profilewire.HTTPError{Type: "http.error", ID: id, Detail: "Target request failed"})
		return
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
		p.stop(&TransportError{Operation: "profile", RequestID: p.RequestID, Err: err})
	}
}
