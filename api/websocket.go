package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// OpenWebSocket establishes an authenticated API connection, not a target connection.
// It inherits explicit dial/TLS settings but never adopts proxy environment variables.
func (c *Client) OpenWebSocket(ctx context.Context, path string) (*websocket.Conn, error) {
	ctx, cancel, err := c.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	endpoint := strings.Replace(c.baseURL, "https://", "wss://", 1)
	endpoint = strings.Replace(endpoint, "http://", "ws://", 1) + path
	headers := http.Header{"Authorization": []string{"Bearer " + c.key}}
	for attempt := 0; ; attempt++ {
		conn, response, err := c.websocket.DialContext(ctx, endpoint, headers)
		if err == nil {
			return conn, nil
		}
		failure := transportError(ctx, err)
		if response == nil || response.Body == nil {
			return nil, failure
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			return nil, &Error{Code: "protocol_error", Message: "Profile handshake rejected", Status: response.StatusCode}
		}
		serviceError := decodeError(data, response.StatusCode)
		if serviceError.Code == "" || serviceError.Message == "" || serviceError.RequestID == "" {
			serviceError = &Error{Code: "protocol_error", Message: "Profile handshake rejected", Status: response.StatusCode}
		}
		delay, retry := websocketRetryDelay(response.Header.Get("Retry-After"))
		if serviceError.Code == "maintenance" && retry && attempt < 2 {
			if err := sleep(ctx, delay); err != nil {
				return nil, transportError(ctx, err)
			}
			continue
		}
		return nil, serviceError
	}
}

func websocketRetryDelay(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 && seconds <= 86400 {
		return time.Duration(seconds * float64(time.Second)), true
	}
	if at, err := http.ParseTime(value); err == nil {
		delay := time.Until(at)
		if delay < 0 {
			delay = 0
		}
		return delay, true
	}
	return 0, false
}
