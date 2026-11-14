package nullgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"

	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
)

// FwcimGeometry contains caller-observed CSS pixel measurements.
type FwcimGeometry struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// FwcimOptions contains observed form and navigation data.
type FwcimOptions struct {
	Form          string
	Timing        map[string]float64
	Inputs        []PreparedInput
	Actions       []Action
	Cookies       map[string]string
	Submitted     *bool
	Referrer      string
	HistoryLength *int
}

func (p *Page) prepareFwcimInputs(fields []PreparedInput, formSelector string) ([]PreparedInput, error) {
	base := make([]PreparedInput, len(fields))
	observations := make([]document.FormInput, len(fields))
	for i, field := range fields {
		base[i] = field
		base[i].Geometry, base[i].Checksum, base[i].Text = nil, nil, nil
		for name := range field.Attributes {
			if name != "id" && name != "name" {
				return nil, errors.New("nullgate: invalid FWCIM input attributes")
			}
		}
		observations[i] = document.FormInput{Attributes: field.Attributes, Selector: field.Selector, SensitiveExtras: field.Checksum != nil || field.Text != nil}
	}
	if err := document.ValidateForm(p.html, formSelector, observations); err != nil {
		return nil, err
	}
	prepared, err := p.prepareInputs(base)
	if err != nil {
		return nil, err
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
		prepared[i].Geometry, prepared[i].Checksum, prepared[i].Text = field.Geometry, field.Checksum, field.Text
	}
	return prepared, nil
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

func prepareFwcimActions(actions []Action) ([]Action, error) {
	invalid := errors.New("nullgate: FWCIM actions contain unsupported fields or invalid values")
	// Capture custom marshaling once, then validate and send only detached JSON.
	data, err := json.Marshal(actions)
	if err != nil {
		return nil, invalid
	}
	var detached []Action
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
func (p *Page) Fwcim(ctx context.Context, opts FwcimOptions) (*FwcimResult, error) {
	start, ok := opts.Timing["navigationStart"]
	if !ok || start <= 0 || math.IsNaN(start) || math.IsInf(start, 0) || math.Trunc(start) != start {
		return nil, errors.New("nullgate: timing requires observed navigationStart milliseconds")
	}
	for _, value := range opts.Timing {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < 0 || (value != 0 && value < start) {
			return nil, errors.New("nullgate: invalid FWCIM navigation timing")
		}
	}
	if p.explicitStartedAt && start != float64(p.startedAtMS) {
		return nil, errors.New("nullgate: navigationStart must match the explicit page start")
	}
	if opts.HistoryLength != nil && *opts.HistoryLength < 1 {
		return nil, errors.New("nullgate: history length must be positive")
	}
	if opts.Form != "" && strings.TrimSpace(opts.Form) == "" {
		return nil, errors.New("nullgate: invalid FWCIM form selector")
	}
	inputs, err := p.prepareFwcimInputs(opts.Inputs, opts.Form)
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
	var result *FwcimResult
	err = p.session.run(ctx, "amazon", "fwcim", p, fields, "", func(data map[string]any) error {
		var err error
		result, err = decodeFwcim(data, p.session.client)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
