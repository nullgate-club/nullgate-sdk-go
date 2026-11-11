package nullgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"unicode/utf16"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
	"golang.org/x/net/http/httpguts"
)

// FwcimGeometry contains only caller-observed CSS pixel measurements.
type FwcimGeometry struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// FwcimInput identifies a nonpassword input or textarea. Value is summarized
// locally; Text optionally sends nonpassword text for the collector canvas.
// Selector disambiguates duplicate IDs/names and must confirm both when supplied.
type FwcimInput struct {
	ID       string
	Name     string
	Selector string
	Value    string
	Geometry *FwcimGeometry
	Text     *string
}

func (FwcimInput) String() string     { return "nullgate.FwcimInput{Value:<redacted>, Text:<redacted>}" }
func (p FwcimInput) GoString() string { return p.String() }

// FwcimParams needs observed navigation timestamps in Unix milliseconds.
// navigationStart must equal Page.StartedAtMS when that observation is supplied.
// Nil Inputs/Actions omit observations; non-nil empty slices explicitly send [].
// Submitted defaults to true; use a pointer to false for an unsubmitted form.
type FwcimParams struct {
	Page              Page
	Cookies           map[string]string
	FormSelector      string
	Inputs            []FwcimInput
	Actions           []Action
	Submitted         *bool
	Referrer          string
	HistoryLength     *int
	PerformanceTiming map[string]int64
}

func (FwcimParams) String() string {
	return "nullgate.FwcimParams{Page:<redacted>, Inputs:<redacted>, Cookies:<redacted>}"
}
func (p FwcimParams) GoString() string { return p.String() }

// FwcimSolution supplies a form field, not an encoded body or login request.
// Insert Metadata1 into the caller's form and URL-encode that form exactly once.
type FwcimSolution struct {
	Metadata1 string
	SendAt    float64
	Headers   map[string]string
	RequestID string
}

func (FwcimSolution) String() string {
	return "nullgate.FwcimSolution{Metadata1:<redacted>, Headers:<redacted>}"
}
func (s FwcimSolution) GoString() string { return s.String() }

// Wait honors the absolute Unix-seconds deadline and caller cancellation.
func (s *FwcimSolution) Wait(ctx context.Context) error {
	return (&Solution{SendAt: s.SendAt, RequestID: s.RequestID}).Wait(ctx)
}

type fwcimPreparedInput struct {
	Attributes map[string]string `json:"attributes"`
	Selector   *string           `json:"selector,omitempty"`
	Value      InputValue        `json:"value"`
	Checksum   uint32            `json:"checksum"`
	Geometry   *FwcimGeometry    `json:"geometry,omitempty"`
	Text       *string           `json:"text,omitempty"`
}

type fwcimWebsite struct {
	websitePayload
	Referrer      string `json:"referrer"`
	HistoryLength *int   `json:"history_length,omitempty"`
}

type fwcimPayload struct {
	Website           fwcimWebsite          `json:"website"`
	Timezone          *string               `json:"timezone,omitempty"`
	Cookies           map[string]string     `json:"cookies"`
	FormSelector      string                `json:"form_selector,omitempty"`
	Inputs            *[]fwcimPreparedInput `json:"inputs,omitempty"`
	Actions           *[]Action             `json:"actions,omitempty"`
	Submitted         bool                  `json:"submitted"`
	PerformanceTiming map[string]int64      `json:"performance_timing"`
}

// fwcimChecksum is standard CRC32 over CESU-8: each UTF-16 unit is encoded
// separately, so supplementary characters occupy six bytes.
func fwcimChecksum(value string) uint32 {
	encoded := make([]byte, 0, len(value))
	appendUnit := func(unit uint16) {
		switch {
		case unit < 0x80:
			encoded = append(encoded, byte(unit))
		case unit < 0x800:
			encoded = append(encoded, byte(0xc0|unit>>6), byte(0x80|unit&0x3f))
		default:
			encoded = append(encoded, byte(0xe0|unit>>12), byte(0x80|unit>>6&0x3f), byte(0x80|unit&0x3f))
		}
	}
	for _, r := range value {
		if r > 0xffff {
			high, low := utf16.EncodeRune(r)
			appendUnit(uint16(high))
			appendUnit(uint16(low))
		} else {
			appendUnit(uint16(r))
		}
	}
	return crc32.ChecksumIEEE(encoded)
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == name {
			return attribute.Val
		}
	}
	return ""
}

func passwordControl(node *html.Node) bool {
	if strings.EqualFold(strings.TrimSpace(htmlAttribute(node, "type")), "password") {
		return true
	}
	for _, token := range strings.Fields(strings.ToLower(htmlAttribute(node, "autocomplete"))) {
		if token == "current-password" || token == "new-password" {
			return true
		}
	}
	for _, attribute := range []string{"id", "name"} {
		value := strings.ToLower(strings.TrimSpace(htmlAttribute(node, attribute)))
		if value == "password" || value == "ap_password" {
			return true
		}
	}
	return false
}

var fwcimControls = cascadia.MustCompile("input, textarea")
var fwcimTemplates = cascadia.MustCompile("template")

func prepareFwcimInputs(page Page, fields []FwcimInput, formSelector string) ([]fwcimPreparedInput, error) {
	document, err := html.Parse(strings.NewReader(page.HTML))
	if err != nil {
		return nil, errors.New("nullgate: could not parse Page.HTML")
	}
	controls := cascadia.QueryAll(document, fwcimControls)
	for _, node := range controls {
		if !passwordControl(node) {
			continue
		}
		for _, attribute := range node.Attr {
			// Original HTML retains duplicate values even when DOM lookup ignores them.
			if attribute.Key == "value" && attribute.Val != "" {
				return nil, errors.New("nullgate: Page.HTML must not contain password values")
			}
		}
		if node.Data == "textarea" && node.FirstChild != nil {
			return nil, errors.New("nullgate: Page.HTML must not contain password values")
		}
	}
	// Native selectors do not traverse a template's separate content fragment.
	for _, template := range cascadia.QueryAll(document, fwcimTemplates) {
		template.FirstChild, template.LastChild = nil, nil
	}
	controls = cascadia.QueryAll(document, fwcimControls)
	scope := document
	if formSelector != "" {
		selector, err := cascadia.Compile(formSelector)
		if err != nil {
			return nil, errors.New("nullgate: invalid FWCIM form selector")
		}
		forms := cascadia.QueryAll(document, selector)
		if len(forms) != 1 || forms[0].Data != "form" {
			return nil, errors.New("nullgate: FWCIM form selector must select exactly one form")
		}
		scope = forms[0]
		controls = cascadia.QueryAll(scope, fwcimControls)
	}
	prepared := make([]fwcimPreparedInput, len(fields))
	for i, field := range fields {
		var matches []*html.Node
		if field.Selector != "" {
			selector, err := cascadia.Compile(field.Selector)
			if err != nil {
				return nil, errors.New("nullgate: invalid FWCIM input selector")
			}
			matches = cascadia.QueryAll(scope, selector)
		} else {
			if field.ID == "" && field.Name == "" {
				return nil, errors.New("nullgate: FWCIM input requires id, name, or selector")
			}
			for _, node := range controls {
				if (field.ID == "" || htmlAttribute(node, "id") == field.ID) && (field.Name == "" || htmlAttribute(node, "name") == field.Name) {
					matches = append(matches, node)
				}
			}
		}
		if len(matches) != 1 || (matches[0].Data != "input" && matches[0].Data != "textarea") ||
			(field.ID != "" && htmlAttribute(matches[0], "id") != field.ID) || (field.Name != "" && htmlAttribute(matches[0], "name") != field.Name) {
			return nil, errors.New("nullgate: FWCIM input must match exactly one input or textarea with matching id/name")
		}
		if passwordControl(matches[0]) {
			return nil, errors.New("nullgate: password input observations are not allowed")
		}
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
		attributes := map[string]string{}
		if field.ID != "" {
			attributes["id"] = field.ID
		}
		if field.Name != "" {
			attributes["name"] = field.Name
		}
		prepared[i] = fwcimPreparedInput{Attributes: attributes, Value: PrepareInputs([]Input{{"value": field.Value}})[0].Value, Checksum: fwcimChecksum(field.Value), Geometry: field.Geometry, Text: field.Text}
		if field.Selector != "" {
			selector := field.Selector
			prepared[i].Selector = &selector
		}
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

func makeFwcimPayload(params FwcimParams, timezone *string, previous websitePayload) (fwcimPayload, error) {
	var payload fwcimPayload
	start, present := params.PerformanceTiming["navigationStart"]
	if !present || start <= 0 {
		return payload, errors.New("nullgate: PerformanceTiming requires observed navigationStart")
	}
	for _, value := range params.PerformanceTiming {
		if value < 0 || (value != 0 && value < start) {
			return payload, errors.New("nullgate: PerformanceTiming timestamps must be zero or at least navigationStart")
		}
	}
	page := params.Page
	if err := validatePage(page); err != nil {
		return payload, err
	}
	observed, err := observePage(page, previous)
	if err != nil {
		return payload, err
	}
	if page.DocumentID == "" && (previous.DocumentID == "" || previous.URL != page.URL || previous.HTML != page.HTML) {
		// Literal pages have no constructor; use the caller's observed start.
		observed.StartedAtMS = start
	}
	if observed.StartedAtMS != start {
		return payload, errors.New("nullgate: PerformanceTiming.navigationStart must match Page document start")
	}
	if params.HistoryLength != nil && *params.HistoryLength < 1 {
		return payload, errors.New("nullgate: HistoryLength must be positive")
	}
	inputs, err := prepareFwcimInputs(page, params.Inputs, params.FormSelector)
	if err != nil {
		return payload, err
	}
	actions, err := prepareFwcimActions(params.Actions)
	if err != nil {
		return payload, err
	}
	payload = fwcimPayload{Website: fwcimWebsite{websitePayload: observed, Referrer: params.Referrer, HistoryLength: params.HistoryLength}, Timezone: timezone, Cookies: params.Cookies, FormSelector: params.FormSelector, Submitted: true, PerformanceTiming: params.PerformanceTiming}
	if payload.Cookies == nil {
		payload.Cookies = map[string]string{}
	}
	if params.Submitted != nil {
		payload.Submitted = *params.Submitted
	}
	if params.Inputs != nil {
		payload.Inputs = &inputs
	}
	if params.Actions != nil {
		payload.Actions = &actions
	}
	return payload, nil
}

// Fwcim calls only the Amazon Nullgate endpoint. It does not discover scripts,
// execute JavaScript, encrypt passwords, send credentials, or submit target forms.
func (s *Session) Fwcim(ctx context.Context, params FwcimParams) (*FwcimSolution, error) {
	if ctx == nil {
		return nil, errors.New("nullgate: context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.amazonGate <- struct{}{}:
		defer func() { <-s.amazonGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrClosed
	case <-s.client.done:
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	stateID, previous, closed := s.amazonStateID, s.amazonDocument, s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return nil, ErrClosed
	}
	payload, err := makeFwcimPayload(params, s.timezone, previous)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("nullgate: FWCIM params must contain JSON-serializable values")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.amazonBaseURL+"/v1/"+s.identity+"/generate?type=fwcim", bytes.NewReader(body))
	if err != nil {
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	request.GetBody = nil
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || s.client.closed.Load() {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.amazonDocument = payload.Website.websitePayload
	s.mu.Unlock()
	request.Header.Set("Authorization", "Bearer "+s.client.apiKey)
	request.Header.Set("User-Agent", s.userAgent)
	request.Header.Set("X-State-ID", stateID)
	request.Header.Set("X-Nullgate-Error-Format", "1")
	request.Header.Set("Content-Type", "application/json")
	response, err := s.generationRequest(request, body)
	if err != nil {
		if errors.Is(err, ErrClosed) {
			return nil, ErrClosed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	defer response.Body.Close()
	s.mu.Lock()
	if values, exists := response.Header[http.CanonicalHeaderKey("X-State-ID")]; exists && !s.closed {
		s.amazonStateID = ""
		if len(values) > 0 {
			s.amazonStateID = values[0]
		}
	}
	closed = s.closed
	s.mu.Unlock()
	if closed || s.client.closed.Load() {
		return nil, ErrClosed
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &TransportError{Operation: "generate", Err: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, responseError(response, data)
	}
	return normalizeFwcimSolution(response, data)
}

func normalizeFwcimSolution(response *http.Response, data []byte) (*FwcimSolution, error) {
	requestID := response.Header.Get("X-Request-ID")
	invalid := func(problem string) (*FwcimSolution, error) {
		return nil, &ProtocolError{Problem: problem, RequestID: requestID}
	}
	if requestID == "" {
		return invalid("missing X-Request-ID")
	}
	var generated struct {
		Metadata1 *string            `json:"metadata1"`
		SendAt    *float64           `json:"send_at"`
		Headers   map[string]*string `json:"headers"`
	}
	if err := json.Unmarshal(data, &generated); err != nil {
		return invalid("expected a JSON object with typed fields")
	}
	if generated.Metadata1 == nil {
		return invalid("missing or invalid metadata1")
	}
	if generated.SendAt == nil || math.IsNaN(*generated.SendAt) || math.IsInf(*generated.SendAt, 0) {
		return invalid("missing or invalid send_at")
	}
	if generated.Headers == nil {
		return invalid("missing or invalid headers")
	}
	headers := make(map[string]string, len(generated.Headers))
	for name, value := range generated.Headers {
		if value == nil || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(*value) {
			return invalid("invalid target header")
		}
		canonical := http.CanonicalHeaderKey(name)
		if previous, exists := headers[canonical]; exists && previous != *value {
			return invalid("conflicting target headers")
		}
		headers[canonical] = *value
	}
	return &FwcimSolution{Metadata1: *generated.Metadata1, SendAt: *generated.SendAt, Headers: headers, RequestID: requestID}, nil
}
