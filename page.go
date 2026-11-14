package nullgate

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
)

// PageOptions identifies a navigation and its observed start time.
type PageOptions struct {
	DocumentID  string
	StartedAtMS *int64
}

// Page retains a single caller-owned document for local discovery and generation.
type Page struct {
	session               *Session
	url, html, documentID string
	startedAtMS           int64
	explicitStartedAt     bool
}

func (*Page) String() string     { return "nullgate.Page{HTML:<redacted>}" }
func (p *Page) GoString() string { return p.String() }

// Page creates a distinct navigation without contacting the API.
func (s *Session) Page(address, html string, opts PageOptions) (*Page, error) {
	if _, err := absoluteHTTPURL(address); err != nil {
		return nil, newError("invalid_url", "page URL must be an absolute HTTP(S) URL")
	}
	if _, err := document.InputDocument(html); err != nil {
		return nil, newError("invalid_page", err.Error())
	}
	id := opts.DocumentID
	if id == "" {
		value, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		id = value.String()
	} else {
		value, err := uuid.Parse(id)
		if err != nil {
			return nil, newError("invalid_page", "document ID must be a UUID")
		}
		id = value.String()
	}
	started := time.Now().UnixMilli()
	if opts.StartedAtMS != nil {
		if *opts.StartedAtMS < 0 {
			return nil, newError("invalid_page", "page start must be nonnegative")
		}
		started = *opts.StartedAtMS
	}
	return &Page{session: s, url: address, html: html, documentID: id, startedAtMS: started, explicitStartedAt: opts.StartedAtMS != nil}, nil
}

type SensorOptions struct {
	Script, ScriptURL string
	Cookies           map[string]string
	Inputs            []PreparedInput
	Actions           []Action
}

type PixelOptions struct{ Script, ScriptURL, Challenge string }
type SbsdOptions struct {
	Script, ScriptURL string
	Cookies           map[string]string
}

// Sensor generates a caller-owned target request.
func (p *Page) Sensor(ctx context.Context, opts SensorOptions) (*Request, error) {
	url, err := p.script("sensor", opts.ScriptURL)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, newError("invalid_request", "script must not be empty")
	}
	fields := map[string]any{"script_url": url, "script": opts.Script, "cookies": selectCookies(opts.Cookies, "_abck", "bm_sz")}
	if opts.Inputs != nil {
		inputs, err := p.prepareInputs(opts.Inputs)
		if err != nil {
			return nil, err
		}
		fields["inputs"] = inputs
	}
	if opts.Actions != nil {
		if err := validateActions(opts.Actions); err != nil {
			return nil, err
		}
		fields["actions"] = opts.Actions
	}
	return p.generate(ctx, "sensor", fields, opts.Script)
}

// Pixel generates a caller-owned pixel request.
func (p *Page) Pixel(ctx context.Context, opts PixelOptions) (*Request, error) {
	url, challenge, err := p.pixelCandidates(opts.ScriptURL, opts.Challenge)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, newError("invalid_request", "script must not be empty")
	}
	return p.generate(ctx, "pixel", map[string]any{"script_url": url, "script": opts.Script, "challenge": challenge}, "")
}

// Sbsd generates a caller-owned SBSD request.
func (p *Page) Sbsd(ctx context.Context, opts SbsdOptions) (*Request, error) {
	url, err := p.script("sbsd", opts.ScriptURL)
	if err != nil {
		return nil, err
	}
	if opts.Script == "" {
		return nil, newError("invalid_request", "script must not be empty")
	}
	return p.generate(ctx, "sbsd", map[string]any{"script_url": url, "script": opts.Script, "cookies": selectCookies(opts.Cookies, "bm_so", "sbsd_o", "bm_s")}, "")
}

func (p *Page) generate(ctx context.Context, operation string, fields map[string]any, script string) (*Request, error) {
	var result *Request
	err := p.session.run(ctx, "akamai", operation, p, fields, script, func(data map[string]any) error {
		var err error
		result, err = decodeRequest(data, p.url, p.session.client)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
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
