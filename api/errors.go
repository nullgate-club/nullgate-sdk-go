package api

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
	message := "nullgate: " + e.Code + ": " + e.Message
	if e.Status != 0 {
		message += fmt.Sprintf(" (status=%d)", e.Status)
	}
	if e.RequestID != "" {
		message += " request_id=" + e.RequestID
	}
	return message
}
func (e *Error) GoString() string          { return e.Error() }
func (e *Error) Unwrap() error             { return e.Cause }
func NewError(code, message string) *Error { return &Error{Code: code, Message: message} }
func ProtocolError(message string) *Error  { return NewError("protocol_error", message) }
