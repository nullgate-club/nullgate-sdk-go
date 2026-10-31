// Package nullgate discovers supported protections locally, prepares Akamai
// target POSTs, and runs active ThreatMetrix profiles. Target HTTP stays caller-owned.
package nullgate

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// Page retains the caller's original document. Discovery assigns one observation
// to all protections; DocumentID and StartedAtMS may also be supplied together.
// Literal pages without observations reuse a session-local context for equal
// URL and HTML. Fresh discovery or a new session distinguishes identical pages.
type Page struct {
	URL         string
	HTML        string
	DocumentID  string
	StartedAtMS *int64
}

func (p Page) String() string   { return "nullgate.Page{HTML:<redacted>}" }
func (p Page) GoString() string { return p.String() }

// ScriptReference identifies a classic script tag in the supplied document.
// TagIndex and Column are zero-based; Line is one-based. RawSource is the
// decoded src attribute, before URL resolution.
type ScriptReference struct {
	RawSource string
	TagIndex  int
	Line      int
	Column    int
}

// Protection is one of the supported concrete candidates. Discovery is a
// heuristic, not a claim that the source has been fetched or validated.
type Protection interface {
	Kind() string
	Provider() string
	protection()
}

// Pixel retains a script candidate and one possible inline challenge.
type Pixel struct {
	Page       Page
	ScriptURL  string
	Challenge  string
	Provenance *ScriptReference
	// ChallengeOffset is a zero-based UTF-8 byte offset, nil for manual values.
	ChallengeOffset *int
}

func (Pixel) Kind() string       { return "pixel" }
func (Pixel) Provider() string   { return "akamai" }
func (Pixel) protection()        {}
func (Pixel) String() string     { return "nullgate.Pixel{Page:<redacted>, Challenge:<redacted>}" }
func (p Pixel) GoString() string { return p.String() }

// Sensor is an extensionless classic-script candidate, or a caller-identified sensor.
type Sensor struct {
	Page       Page
	ScriptURL  string
	Provenance *ScriptReference
}

func (Sensor) Kind() string       { return "sensor" }
func (Sensor) Provider() string   { return "akamai" }
func (Sensor) protection()        {}
func (Sensor) String() string     { return "nullgate.Sensor{Page:<redacted>}" }
func (p Sensor) GoString() string { return p.String() }

// Sbsd retains an SBSD script and its document provenance.
type Sbsd struct {
	Page       Page
	ScriptURL  string
	Provenance *ScriptReference
}

func (Sbsd) Kind() string       { return "sbsd" }
func (Sbsd) Provider() string   { return "akamai" }
func (Sbsd) protection()        {}
func (Sbsd) String() string     { return "nullgate.Sbsd{Page:<redacted>}" }
func (p Sbsd) GoString() string { return p.String() }

// ThreatMetrix retains the actual tags URL and the document that loaded it.
type ThreatMetrix struct {
	Page       Page
	TagsURL    string
	Provenance *ScriptReference
}

func (ThreatMetrix) Kind() string     { return "threatmetrix" }
func (ThreatMetrix) Provider() string { return "threatmetrix" }
func (ThreatMetrix) protection()      {}
func (ThreatMetrix) String() string {
	return "nullgate.ThreatMetrix{Page:<redacted>, TagsURL:<redacted>}"
}
func (p ThreatMetrix) GoString() string { return p.String() }

// ThreatMetrixParams is used only by Session.Profile, not Solve. Inputs and
// Actions use the same observations as SensorParams. Nil omits a collection;
// a non-nil empty slice explicitly clears it.
type ThreatMetrixParams struct {
	Protection ThreatMetrix
	Inputs     []Input
	Actions    []Action
}

func (ThreatMetrixParams) String() string {
	return "nullgate.ThreatMetrixParams{Protection:<redacted>}"
}
func (p ThreatMetrixParams) GoString() string { return p.String() }

// Blocking checks presence of the raw t parameter, including t=; it does not
// decode parameter names or infer blocking from any other part of the URL.
func (p Sbsd) Blocking() bool {
	u, err := url.Parse(p.ScriptURL)
	if err != nil {
		return false
	}
	for part := range strings.SplitSeq(u.RawQuery, "&") {
		name, _, _ := strings.Cut(part, "=")
		if name == "t" {
			return true
		}
	}
	return false
}

// Params is sealed to the three supported, correctly paired operation structs.
// Both value and non-nil pointer forms of these structs are accepted by Solve.
type Params interface {
	params()
}

// PixelParams uses the challenge retained by its Pixel protection.
type PixelParams struct {
	Protection Pixel
	Script     string
}

func (PixelParams) params()            {}
func (PixelParams) String() string     { return "nullgate.PixelParams{Script:<redacted>}" }
func (p PixelParams) GoString() string { return p.String() }

// Input contains field attributes and an optional raw value. Solve hashes the
// value locally and never includes it in the API request.
type Input map[string]string

// Action is a source-supported sensor interaction, in the service's native JSON shape.
type Action map[string]any

// SensorParams preserves nil versus empty Inputs/Actions: nil omits the field,
// while a non-nil empty slice explicitly sends []. Cookies default to {}.
type SensorParams struct {
	Protection Sensor
	Script     string
	Cookies    map[string]string
	Inputs     []Input
	Actions    []Action
}

func (SensorParams) params() {}
func (SensorParams) String() string {
	return "nullgate.SensorParams{Script:<redacted>, Cookies:<redacted>, Inputs:<redacted>}"
}
func (p SensorParams) GoString() string { return p.String() }

// SbsdParams supplies the raw script text and current target cookies.
type SbsdParams struct {
	Protection Sbsd
	Script     string
	Cookies    map[string]string
}

func (SbsdParams) params() {}
func (SbsdParams) String() string {
	return "nullgate.SbsdParams{Script:<redacted>, Cookies:<redacted>}"
}
func (p SbsdParams) GoString() string { return p.String() }

func absoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("expected an absolute HTTP(S) URL")
	}
	return u, nil
}

func validatePage(page Page) error {
	if _, err := absoluteHTTPURL(page.URL); err != nil {
		return fmt.Errorf("Page.URL: %w", err)
	}
	if (page.DocumentID == "") != (page.StartedAtMS == nil) {
		return errors.New("nullgate: Page.DocumentID and Page.StartedAtMS must be supplied together")
	}
	if page.DocumentID != "" {
		if _, err := uuid.Parse(page.DocumentID); err != nil {
			return errors.New("nullgate: Page.DocumentID must be a UUID")
		}
	}
	return nil
}
