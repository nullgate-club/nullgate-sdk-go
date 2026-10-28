package nullgate

import (
	"errors"
	"fmt"
)

// ErrClosed indicates a closed session or client.
var ErrClosed = errors.New("nullgate: client or session is closed")

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
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("nullgate: invalid generation response: %s (request_id=%s)", e.Problem, e.RequestID)
}
func (e *ProtocolError) GoString() string { return e.Error() }

// TransportError keeps errors.Is/errors.As available without rendering an
// underlying request, URL, credentials, or response body in debug output.
type TransportError struct {
	Operation string
	Err       error
}

func (e *TransportError) Error() string    { return "nullgate: " + e.Operation + " transport failed" }
func (e *TransportError) Unwrap() error    { return e.Err }
func (e *TransportError) GoString() string { return e.Error() }
