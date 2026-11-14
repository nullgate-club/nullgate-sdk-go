package protocol

import (
	"context"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"math"
	"regexp"
	"strings"
	"time"
)

func failure(code, message string) *api.Error { return &api.Error{Code: code, Message: message} }
func protocolError(message string) *api.Error { return failure("protocol_error", message) }
func Context(p *browser.Page, state string) map[string]any {
	var current any
	if state != "" {
		current = state
	}
	s := p.Session()
	body := map[string]any{"profile": s.Profile(), "session": current, "user_agent": s.UserAgent(), "url": p.URL(), "html": p.HTML(), "document_id": p.DocumentID(), "started_at_ms": p.StartedAtMS()}
	if timezone := s.Timezone(); timezone != nil {
		body["timezone"] = *timezone
	}
	return body
}
func Wait(ctx context.Context, sendAt float64) error {
	if ctx == nil {
		return failure("invalid_request", "Context must not be nil")
	}
	if math.IsNaN(sendAt) || math.IsInf(sendAt, 0) {
		return protocolError("Invalid send_at")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := sendAt - float64(time.Now().UnixNano())/1e9
		if remaining <= 0 {
			return nil
		}
		// Avoid overflowing time.Duration for an arbitrary server timestamp.
		interval := time.Duration(math.Min(remaining, 3600) * float64(time.Second))
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func Headers(value any) (map[string]string, error) {
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, protocolError("Missing response headers")
	}
	headers := make(map[string]string, len(fields))
	for key, value := range fields {
		text, ok := value.(string)
		if !ok || !headerName.MatchString(key) || strings.ContainsAny(text, "\r\n\x00") {
			return nil, protocolError("Invalid response headers")
		}
		headers[key] = text
	}
	return headers, nil
}
func Timing(data map[string]any) (float64, error) {
	value, ok := data["send_at"].(float64)
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, protocolError("Missing or invalid send_at")
	}
	return value, nil
}
