package nullgate

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"golang.org/x/net/http/httpguts"
)

// Solution is an exact target POST. Body is already encoded: do not marshal it
// again. SendAt is the absolute earliest submission time in Unix seconds.
type Solution struct {
	Method    string
	URL       string
	Headers   map[string]string
	Body      string
	SendAt    float64
	RequestID string
	client    *Client
}

func (s Solution) String() string   { return "nullgate.Solution{Body:<redacted>, Headers:<redacted>}" }
func (s Solution) GoString() string { return s.String() }

// Wait respects the caller's cancellation, including already-expired deadlines.
// It never sends the solution or invents a target-acceptance decision.
func (s *Solution) Wait(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nullgate: context must not be nil")
	}
	if math.IsNaN(s.SendAt) || math.IsInf(s.SendAt, 0) {
		return &ProtocolError{Problem: "send_at must be finite", RequestID: s.RequestID}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		delay := s.SendAt - (float64(now.Unix()) + float64(now.Nanosecond())/float64(time.Second))
		if delay <= 0 {
			return nil
		}
		const maxDuration = time.Duration(1<<63 - 1)
		duration := maxDuration
		if delay < float64(maxDuration)/float64(time.Second) {
			duration = time.Duration(delay * float64(time.Second))
		}
		timer := time.NewTimer(duration)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// Report uses the originating client's anonymous analytics delivery path.
func (s *Solution) Report(ctx context.Context) (bool, error) {
	if s.client == nil {
		return false, errors.New("nullgate: solution has no originating client")
	}
	return s.client.Report(ctx, s.RequestID)
}

func normalizeSolution(response *http.Response, data []byte, operation, target string, client *Client) (*Solution, error) {
	requestID := response.Header.Get("X-Request-ID")
	invalid := func(problem string) (*Solution, error) {
		return nil, &ProtocolError{Problem: problem, RequestID: requestID}
	}
	if requestID == "" {
		return invalid("missing X-Request-ID")
	}
	var generated struct {
		SendAt     *float64           `json:"send_at"`
		Headers    map[string]*string `json:"headers"`
		SensorData *string            `json:"sensor_data"`
		URL        *string            `json:"url"`
		Body       *string            `json:"body"`
	}
	if err := json.Unmarshal(data, &generated); err != nil {
		return invalid("expected a JSON object with typed fields")
	}
	if generated.SendAt == nil || math.IsNaN(*generated.SendAt) || math.IsInf(*generated.SendAt, 0) {
		return invalid("missing or invalid send_at")
	}
	if generated.Headers == nil {
		return invalid("missing or invalid headers")
	}
	headers := make(map[string]string, len(generated.Headers)+1)
	for name, value := range generated.Headers {
		if value == nil || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(*value) {
			return invalid("invalid target header")
		}
		headers[http.CanonicalHeaderKey(name)] = *value
	}
	var body string
	switch operation {
	case "akamai":
		if generated.SensorData == nil {
			return invalid("missing or invalid sensor_data")
		}
		encoded, err := json.Marshal(struct {
			SensorData string `json:"sensor_data"`
		}{SensorData: *generated.SensorData})
		if err != nil {
			return invalid("invalid sensor_data")
		}
		body = string(encoded)
		headers["Content-Type"] = "text/plain;charset=UTF-8"
	case "pixel", "sbsd":
		if generated.URL == nil || generated.Body == nil {
			return invalid("missing or invalid url/body")
		}
		if _, err := absoluteHTTPURL(*generated.URL); err != nil {
			return invalid("target url must be absolute HTTP(S)")
		}
		target, body = *generated.URL, *generated.Body
		if operation == "pixel" {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		} else {
			headers["Content-Type"] = "application/json"
		}
	default:
		return invalid("unsupported operation")
	}
	return &Solution{Method: http.MethodPost, URL: target, Headers: headers, Body: body, SendAt: *generated.SendAt, RequestID: requestID, client: client}, nil
}
