package nullgate

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Only this definitive pre-work rejection can be replayed. Generic service or
// transport failures may have performed work and must never be retried.
func maintenanceDelay(response *http.Response) (time.Duration, bool) {
	if response == nil || response.StatusCode != http.StatusServiceUnavailable ||
		len(response.Header.Values("X-Nullgate-Maintenance")) != 1 ||
		response.Header.Get("X-Nullgate-Maintenance") != "1" || len(response.Header.Values("Retry-After")) != 1 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(response.Header.Get("Retry-After"), 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 5 {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

func (s *Session) waitMaintenance(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return ErrClosed
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrClosed
	case <-s.client.done:
		return ErrClosed
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	closed = s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return ErrClosed
	}
	return nil
}

func (s *Session) generationRequest(request *http.Request, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		// Do not bind active requests to owner lifetimes, but never start after close.
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed || s.client.closed.Load() {
			return nil, ErrClosed
		}
		response, err := s.client.http.Do(request)
		if err != nil {
			return nil, err
		}
		delay, retry := maintenanceDelay(response)
		if !retry {
			return response, nil
		}
		response.Header.Del("X-State-ID")
		if attempt == 2 {
			return response, nil
		}
		response.Body.Close()
		if err := s.waitMaintenance(request.Context(), delay); err != nil {
			return nil, err
		}
		request = request.Clone(request.Context())
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = nil
	}
}
