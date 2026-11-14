package browser

import (
	"github.com/google/uuid"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"strings"
)

func failure(code, message string) *api.Error { return &api.Error{Code: code, Message: message} }

// Options identifies a browser profile and its environment.
type Options struct {
	UserAgent string
	Profile   string
	Timezone  *string
}

// Session identifies a browser visit.
type Session struct {
	userAgent, profile string
	timezone           *string
}

// New creates a local browser session without contacting the API.
func New(opts Options) (*Session, error) {
	if strings.TrimSpace(opts.UserAgent) == "" || strings.ContainsAny(opts.UserAgent, "\r\n") {
		return nil, failure("invalid_request", "user agent must be a nonempty header value")
	}
	profile := opts.Profile
	if profile == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		profile = id.String()
	} else {
		id, err := uuid.Parse(profile)
		if err != nil {
			return nil, failure("invalid_request", "profile must be a UUID")
		}
		profile = id.String()
	}
	var timezone *string
	if opts.Timezone != nil {
		value := *opts.Timezone
		timezone = &value
	}
	return &Session{userAgent: opts.UserAgent, profile: profile, timezone: timezone}, nil
}

func (s *Session) UserAgent() string { return s.userAgent }
func (s *Session) Profile() string   { return s.profile }
func (s *Session) Timezone() *string {
	if s.timezone == nil {
		return nil
	}
	v := *s.timezone
	return &v
}
