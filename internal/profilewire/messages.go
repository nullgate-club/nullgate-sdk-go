// Package profilewire owns the private profiling connection's JSON contract.
package profilewire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/nullgate-club/nullgate-sdk-go/internal/turn"
)

type Command struct {
	Type string `json:"type"`
}

type Collector struct {
	URL       string `json:"url"`
	OrgID     string `json:"org_id"`
	SessionID string `json:"session_id"`
}

type Hello struct {
	Type      string `json:"type"`
	StateID   string `json:"state_id"`
	RequestID string `json:"request_id"`
}

type Notice struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

type Pagehide struct {
	Type      string `json:"type"`
	AtMS      int64  `json:"at_ms"`
	Persisted bool   `json:"persisted"`
}

type ServiceError struct {
	Type      string          `json:"type"`
	Status    int             `json:"status"`
	Detail    json.RawMessage `json:"detail"`
	RequestID string          `json:"request_id"`
}

type HTTPRequest struct {
	Role        string            `json:"role"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        *string           `json:"body"`
	Credentials string            `json:"credentials"`
}

type HTTP struct {
	Type    string       `json:"type"`
	ID      *int64       `json:"id"`
	Request *HTTPRequest `json:"request"`
}

type HTTPResponse struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`
	ReceivedAtMS int64             `json:"received_at_ms"`
}

type HTTPResult struct {
	Type     string       `json:"type"`
	ID       int64        `json:"id"`
	Response HTTPResponse `json:"response"`
}

type HTTPError struct {
	Type   string `json:"type"`
	ID     int64  `json:"id"`
	Detail string `json:"detail"`
}

type ICE struct {
	Type   string       `json:"type"`
	ID     *int64       `json:"id"`
	Server *turn.Server `json:"server"`
}

type ICERelease struct {
	Type string `json:"type"`
	ID   *int64 `json:"id"`
}

type ICEResult struct {
	Type        string            `json:"type"`
	ID          int64             `json:"id"`
	Observation *turn.Observation `json:"observation"`
}

// Decode rejects unknown fields and any additional JSON value after the frame.
func Decode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing JSON")
	}
	return nil
}
