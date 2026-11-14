package acic

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/protocol"
)

type Client struct{ connection *api.Client }

func New(connection *api.Client) *Client { return &Client{connection: connection} }

type PowOptions struct {
	ChallengeType, HTML string
	StartedAtMS         *int64
}
type PowResult struct {
	Response string
	SendAt   float64
}

func (r *PowResult) Wait(ctx context.Context) error { return protocol.Wait(ctx, r.SendAt) }
func (c *Client) Pow(ctx context.Context, opts PowOptions) (*PowResult, error) {
	body := map[string]any{"challenge_type": opts.ChallengeType, "html": opts.HTML}
	if opts.StartedAtMS != nil {
		body["started_at_ms"] = *opts.StartedAtMS
	}
	var result struct {
		Response  *string  `json:"response"`
		SendAt    *float64 `json:"send_at"`
		RequestID *string  `json:"request_id"`
	}
	if err := c.connection.Call(ctx, "/amazon/acic/pow", body, &result, "", false); err != nil {
		return nil, err
	}
	if result.Response == nil || result.SendAt == nil || result.RequestID == nil || math.IsNaN(*result.SendAt) || math.IsInf(*result.SendAt, 0) {
		return nil, api.ProtocolError("Invalid ACIC response")
	}
	return &PowResult{Response: *result.Response, SendAt: *result.SendAt}, nil
}

type WafOptions struct{ Problem json.RawMessage }
type WafResult struct{ ClientSolution []int }

func (c *Client) Waf(ctx context.Context, opts WafOptions) (*WafResult, error) {
	var problem map[string]json.RawMessage
	if err := json.Unmarshal(opts.Problem, &problem); err != nil || problem == nil {
		return nil, errors.New("invalid WAF problem")
	}
	var result struct {
		ClientSolution *[]int  `json:"client_solution"`
		RequestID      *string `json:"request_id"`
	}
	if err := c.connection.Call(ctx, "/amazon/acic/waf", map[string]any{"problem": opts.Problem}, &result, "", false); err != nil {
		return nil, err
	}
	if result.ClientSolution == nil || result.RequestID == nil {
		return nil, api.ProtocolError("Invalid ACIC response")
	}
	return &WafResult{ClientSolution: *result.ClientSolution}, nil
}
func (r *WafResult) VerificationBody(problem json.RawMessage, elapsedSeconds float64, locale string) (json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(problem, &values); err != nil || values == nil {
		return nil, errors.New("invalid WAF problem")
	}
	for _, key := range []string{"state", "key", "hmac_tag"} {
		if _, ok := values[key]; !ok {
			return nil, errors.New("missing WAF problem field: " + key)
		}
	}
	if math.IsNaN(elapsedSeconds) || math.IsInf(elapsedSeconds, 0) || elapsedSeconds*1000 > float64(math.MaxInt64) || elapsedSeconds*1000 < float64(math.MinInt64) {
		return nil, errors.New("invalid elapsed time")
	}
	return json.Marshal(map[string]any{"state": values["state"], "key": values["key"], "hmac_tag": values["hmac_tag"], "client_solution": r.ClientSolution, "metrics": map[string]any{"solve_time_millis": int64(elapsedSeconds * 1000)}, "locale": locale})
}
