package akamai

import (
	"context"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
)

type SensorOptions struct {
	Script, ScriptURL string
	Cookies           map[string]string
	Inputs            []browser.PreparedInput
	Actions           []browser.Action
}

type PixelOptions struct{ Script, ScriptURL, Challenge string }
type SbsdOptions struct {
	Script, ScriptURL string
	Cookies           map[string]string
}

// Sensor generates a caller-owned target request.
func (s *Session) Sensor(ctx context.Context, p *browser.Page, opts SensorOptions) (*Request, error) {
	if err := s.validate(ctx, p); err != nil {
		return nil, err
	}
	url, err := scriptURL(p, "sensor", opts.ScriptURL)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, failure("invalid_request", "script must not be empty")
	}
	fields := map[string]any{"script_url": url, "script": opts.Script, "cookies": selectCookies(opts.Cookies, "_abck", "bm_sz")}
	if opts.Inputs != nil {
		inputs, err := p.PrepareInputs(opts.Inputs)
		if err != nil {
			return nil, err
		}
		fields["inputs"] = inputs
	}
	if opts.Actions != nil {
		if err := browser.ValidateActions(opts.Actions); err != nil {
			return nil, err
		}
		fields["actions"] = opts.Actions
	}
	return s.generate(ctx, p, "sensor", fields, opts.Script)
}

// Pixel generates a caller-owned pixel request.
func (s *Session) Pixel(ctx context.Context, p *browser.Page, opts PixelOptions) (*Request, error) {
	if err := s.validate(ctx, p); err != nil {
		return nil, err
	}
	url, challenge, err := pixelCandidates(p, opts.ScriptURL, opts.Challenge)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, failure("invalid_request", "script must not be empty")
	}
	return s.generate(ctx, p, "pixel", map[string]any{"script_url": url, "script": opts.Script, "challenge": challenge}, "")
}

// Sbsd generates a caller-owned SBSD request.
func (s *Session) Sbsd(ctx context.Context, p *browser.Page, opts SbsdOptions) (*Request, error) {
	if err := s.validate(ctx, p); err != nil {
		return nil, err
	}
	url, err := scriptURL(p, "sbsd", opts.ScriptURL)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, failure("invalid_request", "script must not be empty")
	}
	return s.generate(ctx, p, "sbsd", map[string]any{"script_url": url, "script": opts.Script, "cookies": selectCookies(opts.Cookies, "bm_so", "sbsd_o", "bm_s")}, "")
}

func selectCookies(cookies map[string]string, names ...string) map[string]string {
	result := make(map[string]string)
	for _, name := range names {
		if value, ok := cookies[name]; ok {
			result[name] = value
		}
	}
	return result
}
