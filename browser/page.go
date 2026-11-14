package browser

import (
	"github.com/google/uuid"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
	"time"
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
	if _, err := api.AbsoluteHTTPURL(address); err != nil {
		return nil, failure("invalid_url", "page URL must be an absolute HTTP(S) URL")
	}
	if _, err := document.InputDocument(html); err != nil {
		return nil, failure("invalid_page", err.Error())
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
			return nil, failure("invalid_page", "document ID must be a UUID")
		}
		id = value.String()
	}
	started := time.Now().UnixMilli()
	if opts.StartedAtMS != nil {
		if *opts.StartedAtMS < 0 {
			return nil, failure("invalid_page", "page start must be nonnegative")
		}
		started = *opts.StartedAtMS
	}
	return &Page{session: s, url: address, html: html, documentID: id, startedAtMS: started, explicitStartedAt: opts.StartedAtMS != nil}, nil
}

func (p *Page) Session() *Session      { return p.session }
func (p *Page) URL() string            { return p.url }
func (p *Page) HTML() string           { return p.html }
func (p *Page) DocumentID() string     { return p.documentID }
func (p *Page) StartedAtMS() int64     { return p.startedAtMS }
func (p *Page) HasExplicitStart() bool { return p.explicitStartedAt }
