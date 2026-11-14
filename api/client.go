// Package api owns authenticated Nullgate connections and API errors.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const maxResponseBytes = 32 << 20

// Client is a shared authenticated API connection. It is safe for concurrent use.
type Client struct {
	key, baseURL  string
	http          *http.Client
	timeout       time.Duration
	ownsTransport bool
	websocket     websocket.Dialer
	closed        atomic.Bool
	gzipDisabled  atomic.Bool
	done          chan struct{}
	lifetime      context.Context
	cancel        context.CancelFunc
}

func (*Client) String() string           { return "api.Client{APIKey:<redacted>}" }
func (c *Client) GoString() string       { return c.String() }
func (c *Client) Done() <-chan struct{}  { return c.done }
func (c *Client) Closed() bool           { return c.closed.Load() }
func (c *Client) Timeout() time.Duration { return c.timeout }
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	close(c.done)
	c.cancel()
	if c.ownsTransport {
		c.http.CloseIdleConnections()
	}
	return nil
}
func (c *Client) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, NewError("invalid_request", "Context must not be nil")
	}
	if c.Closed() {
		return nil, nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	deadline, cancel := context.WithTimeout(ctx, c.timeout)
	stop := context.AfterFunc(c.lifetime, cancel)
	return deadline, func() { stop(); cancel() }, nil
}
func transportError(ctx context.Context, err error) *Error {
	code, message := "transport_error", "API connection failed"
	if ctx.Err() != nil {
		err = ctx.Err()
		if errors.Is(err, context.DeadlineExceeded) {
			code, message = "timeout", "API request timed out"
		}
	}
	return &Error{Code: code, Message: message, Cause: err}
}
func readResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, NewError("protocol_error", "API response exceeds 32 MiB")
	}
	return data, nil
}
func decodeObject(data []byte, out any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return NewError("protocol_error", "Expected a JSON object")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return NewError("protocol_error", "Malformed API response")
	}
	return nil
}
func decodeError(data []byte, status int) *Error {
	var value struct {
		Code      *string `json:"code"`
		Message   *string `json:"message"`
		RequestID *string `json:"request_id"`
	}
	if json.Unmarshal(data, &value) != nil || value.Code == nil || value.Message == nil || value.RequestID == nil {
		return &Error{Code: "protocol_error", Message: "Malformed error response", Status: status}
	}
	return &Error{Code: *value.Code, Message: *value.Message, RequestID: *value.RequestID, Status: status}
}
func retryAfter(raw string) (time.Duration, bool) {
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 5 {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}
func sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
func (c *Client) Call(ctx context.Context, path string, body map[string]any, out any, script string, retry bool) error {
	var plain []byte
	var err error
	method, contentType := http.MethodGet, ""
	if body != nil {
		plain, err = json.Marshal(body)
		if err != nil {
			return NewError("invalid_request", "Request cannot be encoded as JSON")
		}
		method, contentType = http.MethodPost, "application/json"
	}
	return c.exchange(ctx, path, method, contentType, plain, body, out, script, retry)
}

// Multipart preserves raw image bytes, part order, and the original boundary on retry.
func (c *Client) Multipart(ctx context.Context, path, contentType string, body []byte, out any) error {
	return c.exchange(ctx, path, http.MethodPost, contentType, body, nil, out, "", true)
}

func (c *Client) exchange(ctx context.Context, path, method, contentType string, plain []byte, body map[string]any, out any, script string, retry bool) error {
	ctx, cancel, err := c.operationContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	var compressed []byte
	plainFallback, scriptFallback := false, false
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return transportError(ctx, err)
		}
		useGzip := contentType == "application/json" && len(plain) >= 1024 && !plainFallback && !c.gzipDisabled.Load()
		data := plain
		if useGzip {
			if compressed == nil {
				var buf bytes.Buffer
				writer, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
				_, _ = writer.Write(plain)
				_ = writer.Close()
				compressed = buf.Bytes()
			}
			data = compressed
		}
		request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
		if err != nil {
			return NewError("invalid_request", "Invalid API request")
		}
		request.Header.Set("Authorization", "Bearer "+c.key)
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		if useGzip {
			request.Header.Set("Content-Encoding", "gzip")
		}
		response, err := c.http.Do(request)
		if err != nil {
			return transportError(ctx, err)
		}
		raw, err := readResponse(response)
		if err != nil {
			var apiErr *Error
			if errors.As(err, &apiErr) {
				return apiErr
			}
			return transportError(ctx, err)
		}
		if useGzip && (response.StatusCode == 413 || response.StatusCode == 415) {
			if response.StatusCode == 415 {
				c.gzipDisabled.Store(true)
			}
			if retry && !plainFallback && attempt < 2 {
				plainFallback = true
				continue
			}
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return decodeObject(raw, out)
		}
		failure := decodeError(raw, response.StatusCode)
		if failure.Code == "script_required" && script != "" && body != nil && !scriptFallback && attempt < 2 {
			scriptFallback = true
			full := make(map[string]any, len(body))
			for k, v := range body {
				if k != "script_digest" {
					full[k] = v
				}
			}
			full["script"] = script
			plain, err = json.Marshal(full)
			if err != nil {
				return &Error{Code: "invalid_request", Message: "Request cannot be encoded as JSON"}
			}
			compressed = nil
			continue
		}
		if delay, ok := retryAfter(response.Header.Get("Retry-After")); retry && failure.Code == "maintenance" && attempt < 2 && ok {
			if err := sleep(ctx, delay); err != nil {
				return transportError(ctx, err)
			}
			continue
		}
		return failure
	}
}

// Report is anonymous and best effort. Only caller cancellation is an error.
func (c *Client) Report(ctx context.Context, requestID string) (bool, error) {
	if requestID == "" {
		return false, NewError("invalid_request", "RequestID must not be empty")
	}
	if ctx == nil {
		return false, NewError("invalid_request", "Context must not be nil")
	}
	caller := ctx
	ctx, cancel, err := c.operationContext(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	body, _ := json.Marshal(map[string]string{"request_id": requestID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/analytics/report", bytes.NewReader(body))
	if err != nil {
		return false, NewError("invalid_request", "Invalid report request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if caller.Err() != nil {
		if response != nil {
			response.Body.Close()
		}
		return false, caller.Err()
	}
	if err != nil {
		return false, nil
	}
	_, err = readResponse(response)
	if caller.Err() != nil {
		return false, caller.Err()
	}
	return err == nil && ctx.Err() == nil && response.StatusCode >= 200 && response.StatusCode < 300, nil
}
