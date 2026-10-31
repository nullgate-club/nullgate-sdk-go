package nullgate

import (
	"errors"
	"fmt"
)

// ErrClosed indicates a closed session or client.
var ErrClosed = errors.New("nullgate: client or session is closed")

// AmbiguousProtectionError means discovery found more than one candidate.
// Pass false to FindProtections to inspect every candidate and its provenance.
type AmbiguousProtectionError struct {
	Count int
}

func (e *AmbiguousProtectionError) Error() string {
	return fmt.Sprintf("nullgate: found %d protection candidates; use FindProtections(page, false) to inspect and select explicitly", e.Count)
}

// APIError retains the original service status, parsed detail and request ID.
// Its default rendering deliberately omits the detail, which can contain
// caller-supplied content. Inspect Detail explicitly when appropriate.
type APIError struct {
	StatusCode int
	Detail     any
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("nullgate: HTTP %d (request_id=%s)", e.StatusCode, e.RequestID)
}
func (e *APIError) GoString() string { return e.Error() }

// ProtocolError means a successful API response was missing required data or
// had an invalid shape. Problem never includes response bodies or source text.
type ProtocolError struct {
	Problem   string
	RequestID string
	Operation string
}

func (e *ProtocolError) Error() string {
	operation := e.Operation
	if operation == "" {
		operation = "generation"
	}
	return fmt.Sprintf("nullgate: invalid %s response: %s (request_id=%s)", operation, e.Problem, e.RequestID)
}
func (e *ProtocolError) GoString() string { return e.Error() }

// TransportError keeps errors.Is/errors.As available without rendering an
// underlying request, URL, credentials, or response body in debug output.
type TransportError struct {
	Operation string
	Err       error
	RequestID string
}

func (e *TransportError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("nullgate: %s transport failed (request_id=%s)", e.Operation, e.RequestID)
	}
	return "nullgate: " + e.Operation + " transport failed"
}
func (e *TransportError) Unwrap() error    { return e.Err }
func (e *TransportError) GoString() string { return e.Error() }
