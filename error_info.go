package nullgate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrorInfo is optional service-provided metadata. Code permits future values.
type ErrorInfo struct {
	Code      string          `json:"code"`
	Origin    string          `json:"origin"`
	Message   string          `json:"message"`
	Retryable *bool           `json:"retryable"`
	Stage     string          `json:"stage,omitempty"`
	Target    *ErrorTarget    `json:"target,omitempty"`
	Cause     *TransportCause `json:"cause,omitempty"`
	CommandID *int64          `json:"command_id,omitempty"`
}

func (e ErrorInfo) String() string {
	return fmt.Sprintf("ErrorInfo{Code:%s Origin:%s}", safeErrorCode(e.Code), e.Origin)
}
func (e ErrorInfo) GoString() string { return e.String() }

// ErrorTarget contains server-derived target context, never a full URL.
type ErrorTarget struct {
	Role   string `json:"role"`
	Method string `json:"method"`
	Host   string `json:"host"`
}

func (ErrorTarget) String() string     { return "ErrorTarget{<redacted>}" }
func (e ErrorTarget) GoString() string { return e.String() }

// TransportCause contains safe categories, not raw exception messages.
type TransportCause struct {
	Kind string `json:"kind"`
	Type string `json:"type,omitempty"`
	Code string `json:"code,omitempty"`
}

func errorToken(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func safeErrorCode(code string) string {
	if errorToken(code, 128) {
		return code
	}
	return "UNKNOWN"
}

func safeErrorOrigin(origin string) string {
	switch origin {
	case "client", "request", "service", "upstream":
		return origin
	default:
		return "unknown"
	}
}

func parseErrorInfo(raw json.RawMessage) *ErrorInfo {
	var fields map[string]json.RawMessage
	var info ErrorInfo
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(raw, &info) != nil ||
		fields["code"] == nil || string(fields["code"]) == "null" || fields["message"] == nil || string(fields["message"]) == "null" || fields["retryable"] == nil {
		return nil
	}
	switch info.Origin {
	case "client", "request", "service", "upstream":
	default:
		return nil
	}
	if info.Cause != nil && !validCause(*info.Cause) {
		return nil
	}
	if info.CommandID != nil && *info.CommandID <= 0 {
		return nil
	}
	return &info
}

func validCause(cause TransportCause) bool {
	switch cause.Kind {
	case "timeout", "dns", "tls", "proxy", "connection", "cancelled", "invalid_response", "unknown":
	default:
		return false
	}
	return (cause.Type == "" || errorToken(cause.Type, 128)) && (cause.Code == "" || errorToken(cause.Code, 64))
}

func transportCause(err error) TransportCause {
	cause := TransportCause{Kind: "unknown"}
	if err == nil {
		cause.Kind = "invalid_response"
		return cause
	}
	var dns *net.DNSError
	var network net.Error
	var tlsError *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	switch {
	case errors.Is(err, context.Canceled):
		cause.Kind = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		cause.Kind = "timeout"
	case errors.As(err, &network) && network.Timeout():
		cause.Kind = "timeout"
	case errors.As(err, &dns):
		cause.Kind = "dns"
	case errors.As(err, &tlsError), errors.As(err, &record), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &certificate):
		cause.Kind = "tls"
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		cause.Kind = "connection"
	}
	return cause
}
