package amazon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"

	"github.com/nullgate-club/nullgate-sdk-go/v2/amazon/acic"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/protocol"
)

// Input contains a prepared observation and FWCIM-specific measurements.
type Input struct {
	browser.PreparedInput
	Geometry *Geometry `json:"geometry,omitempty"`
	Checksum *uint32   `json:"checksum,omitempty"`
	Text     *string   `json:"text,omitempty"`
}

type Client struct {
	connection *api.Client
	ACIC       *acic.Client
}

func New(connection *api.Client) *Client {
	return &Client{connection: connection, ACIC: acic.New(connection)}
}

type Session struct {
	connection *api.Client
	visit      *browser.Session
	gate       chan struct{}
	state      string
}

func (c *Client) Session(visit *browser.Session) (*Session, error) {
	if c.connection.Closed() {
		return nil, api.ErrClosed
	}
	if visit == nil {
		return nil, api.NewError("invalid_request", "Session must not be nil")
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Session{connection: c.connection, visit: visit, gate: gate}, nil
}

// Geometry contains caller-observed CSS pixel measurements.
type Geometry struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// FwcimOptions contains observed form and navigation data.
type FwcimOptions struct {
	Form          string
	Timing        map[string]float64
	Inputs        []Input
	Actions       []browser.Action
	Cookies       map[string]string
	Submitted     *bool
	Referrer      string
	HistoryLength *int
}

func prepareFwcimInputs(p *browser.Page, fields []Input, formSelector string) ([]Input, error) {
	base := make([]browser.PreparedInput, len(fields))
	observations := make([]document.FormInput, len(fields))
	for i, field := range fields {
		base[i] = field.PreparedInput
		for name := range field.Attributes {
			if name != "id" && name != "name" {
				return nil, errors.New("nullgate: invalid FWCIM input attributes")
			}
		}
		observations[i] = document.FormInput{Attributes: field.Attributes, Selector: field.Selector, SensitiveExtras: field.Checksum != nil || field.Text != nil}
	}
	if err := document.ValidateForm(p.HTML(), formSelector, observations); err != nil {
		return nil, err
	}
	prepared, err := p.PrepareInputs(base)
	if err != nil {
		return nil, err
	}
	result := make([]Input, len(fields))
	if fields == nil {
		result = nil
	}
	for i, field := range fields {
		if g := field.Geometry; g != nil {
			for _, measurement := range []float64{g.Left, g.Top, g.Width, g.Height} {
				if math.IsNaN(measurement) || math.IsInf(measurement, 0) {
					return nil, errors.New("nullgate: FWCIM geometry must be finite")
				}
			}
			if g.Width < 0 || g.Height < 0 {
				return nil, errors.New("nullgate: FWCIM geometry sizes must be nonnegative")
			}
		}
		result[i] = Input{PreparedInput: prepared[i], Geometry: field.Geometry, Checksum: field.Checksum, Text: field.Text}
	}
	return result, nil
}

func actionNumber(value any, integer bool) bool {
	if value == nil {
		return true
	}
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	finite, err := number.Float64()
	if err != nil || math.IsNaN(finite) || math.IsInf(finite, 0) {
		return false
	}
	if integer {
		exact, ok := new(big.Rat).SetString(string(number))
		return ok && exact.IsInt()
	}
	return true
}

func actionVector(value any) bool {
	if value == nil {
		return true
	}
	items, ok := value.([]any)
	if !ok || len(items) != 3 {
		return false
	}
	for _, item := range items {
		if !actionNumber(item, false) {
			return false
		}
	}
	return true
}

func actionTouches(value any) bool {
	touches, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range touches {
		touch, ok := item.(map[string]any)
		if !ok || touch["x"] == nil || touch["y"] == nil {
			return false
		}
		for name, value := range touch {
			if (name != "x" && name != "y" && name != "identifier") ||
				value == nil || !actionNumber(value, name == "identifier") {
				return false
			}
		}
	}
	return true
}

func actionSummary(value any) bool {
	pair, ok := value.([]any)
	if !ok || len(pair) != 2 {
		return false
	}
	nonnegativeInteger := func(value any) bool {
		if value == nil || !actionNumber(value, true) {
			return false
		}
		number, _ := value.(json.Number).Float64()
		return number >= 0
	}
	if !nonnegativeInteger(pair[0]) {
		return false
	}
	if pair[1] == nil {
		return true
	}
	items, ok := pair[1].([]any)
	if !ok || len(items) != 4 {
		return false
	}
	for _, item := range items {
		if !nonnegativeInteger(item) {
			return false
		}
	}
	return true
}

func prepareFwcimActions(actions []browser.Action) ([]browser.Action, error) {
	invalid := errors.New("nullgate: FWCIM actions contain unsupported fields or invalid values")
	// Capture custom marshaling once, then validate and send only detached JSON.
	data, err := json.Marshal(actions)
	if err != nil {
		return nil, invalid
	}
	var detached []browser.Action
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&detached); err != nil {
		return nil, invalid
	}
	for _, action := range detached {
		if action == nil {
			return nil, invalid
		}
		for key, value := range action {
			valid := false
			switch key {
			case "type", "target_path", "pointer_type":
				_, valid = value.(string)
			case "trusted", "shift", "ctrl", "alt", "meta", "absolute":
				_, valid = value.(bool)
				valid = valid || value == nil
			case "target":
				valid = actionNumber(value, true)
			case "time", "x", "y", "button", "which", "pointer_id", "key_code", "char_code", "alpha", "beta", "gamma", "interval", "checksum":
				valid = actionNumber(value, key == "checksum")
				if valid && key == "checksum" && value != nil {
					number, _ := value.(json.Number).Float64()
					valid = number >= 0 && number <= math.MaxUint32
				}
			case "text":
				_, valid = value.(string)
				valid = valid || value == nil
			case "touches":
				valid = actionTouches(value)
			case "acceleration", "acceleration_with_gravity", "rotation_rate":
				valid = actionVector(value)
			case "input_summary":
				valid = actionSummary(value)
			}
			if !valid {
				return nil, invalid
			}
		}
	}
	return detached, nil
}

// Fwcim prepares form observations locally and requests a metadata field.
// The caller remains responsible for submitting the target form.
func (s *Session) Fwcim(ctx context.Context, p *browser.Page, opts FwcimOptions) (*FwcimResult, error) {
	if ctx == nil {
		return nil, api.NewError("invalid_request", "Context must not be nil")
	}
	if p == nil || p.Session() != s.visit {
		return nil, api.NewError("invalid_request", "Page must belong to session")
	}
	start, ok := opts.Timing["navigationStart"]
	if !ok || start <= 0 || math.IsNaN(start) || math.IsInf(start, 0) || math.Trunc(start) != start {
		return nil, errors.New("nullgate: timing requires observed navigationStart milliseconds")
	}
	for _, value := range opts.Timing {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < 0 || (value != 0 && value < start) {
			return nil, errors.New("nullgate: invalid FWCIM navigation timing")
		}
	}
	if p.HasExplicitStart() && start != float64(p.StartedAtMS()) {
		return nil, errors.New("nullgate: navigationStart must match the explicit page start")
	}
	if opts.HistoryLength != nil && *opts.HistoryLength < 1 {
		return nil, errors.New("nullgate: history length must be positive")
	}
	if opts.Form != "" && strings.TrimSpace(opts.Form) == "" {
		return nil, errors.New("nullgate: invalid FWCIM form selector")
	}
	inputs, err := prepareFwcimInputs(p, opts.Inputs, opts.Form)
	if err != nil {
		return nil, err
	}
	actions, err := prepareFwcimActions(opts.Actions)
	if err != nil {
		return nil, err
	}
	cookies := make(map[string]string)
	for _, name := range []string{"session-id", "session-token", "ubid-main"} {
		if value, exists := opts.Cookies[name]; exists {
			cookies[name] = value
		}
	}
	submitted := true
	if opts.Submitted != nil {
		submitted = *opts.Submitted
	}
	fields := map[string]any{
		"started_at_ms":      start,
		"performance_timing": opts.Timing,
		"submitted":          submitted,
		"referrer":           opts.Referrer,
		"cookies":            cookies,
	}
	if opts.Form != "" {
		fields["form_selector"] = opts.Form
	}
	if opts.HistoryLength != nil {
		fields["history_length"] = *opts.HistoryLength
	}
	if opts.Inputs != nil {
		fields["inputs"] = inputs
	}
	if opts.Actions != nil {
		fields["actions"] = actions
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.connection.Done():
		return nil, api.ErrClosed
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.connection.Closed() {
		return nil, api.ErrClosed
	}
	body := protocol.Context(p, s.state)
	for key, value := range fields {
		body[key] = value
	}
	var data map[string]any
	if err := s.connection.Call(ctx, "/amazon/fwcim", body, &data, "", true); err != nil {
		return nil, err
	}
	result, err := decodeFwcim(data, s.connection)
	if err != nil {
		return nil, err
	}
	state, ok := data["session"].(string)
	if !ok || state == "" {
		return nil, api.ProtocolError("Missing response session")
	}
	s.state = state
	return result, nil
}
