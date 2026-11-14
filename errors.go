package nullgate

import (
	"errors"
	"fmt"
)

// ErrClosed indicates a closed client or session.
var ErrClosed = errors.New("nullgate: client or session is closed")

// Error is an API, protocol, validation, or transport failure.
// Cause preserves errors.Is and errors.As without printing request bodies or credentials.
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Status    int    `json:"-"`
	Cause     error  `json:"-"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("nullgate: %s (status=%d request_id=%s)", e.Code, e.Status, e.RequestID)
}
func (e *Error) GoString() string          { return e.Error() }
func (e *Error) Unwrap() error             { return e.Cause }
func newError(code, message string) *Error { return &Error{Code: code, Message: message} }
func protocolError(message string) *Error  { return newError("protocol_error", message) }
