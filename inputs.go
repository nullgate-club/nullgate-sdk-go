package nullgate

import (
	"sort"
	"strings"

	"github.com/andybalholm/cascadia"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
)

// Input contains field attributes and a raw value to summarize locally.
type Input map[string]string

// Action contains an interaction in the service's JSON shape.
type Action map[string]any

// InputValue is a privacy-preserving UTF-16 summary, matching JavaScript field
// lengths. Counts are total code units, special code units, ASCII letters after
// lowercasing, and ASCII digits, respectively. Optional comparison facts use
// pointers so that a computed zero is distinct from an absent observation.
type InputValue struct {
	Length        int     `json:"length"`
	Hash          string  `json:"hash"`
	Counts        *[4]int `json:"counts,omitempty"`
	Hash31        *int32  `json:"hash31,omitempty"`
	TrimmedHash31 *int32  `json:"trimmed_hash31,omitempty"`
	TrimmedLength *int    `json:"trimmed_length,omitempty"`
}

// PreparedInput retains a summary. Text, when set, contains raw nonpassword canvas text.
type PreparedInput struct {
	Attributes map[string]string `json:"attributes"`
	Selector   *string           `json:"selector,omitempty"`
	Value      InputValue        `json:"value"`
	Geometry   *FwcimGeometry    `json:"geometry,omitempty"`
	Checksum   *uint32           `json:"checksum,omitempty"`
	Text       *string           `json:"text,omitempty"`
}

// PrepareInputs hashes UTF-16LE bytes locally, preserving field order and all
// attributes except value and the top-level selector. It does not mutate its argument.
func PrepareInputs(inputs []Input) []PreparedInput {
	prepared := make([]PreparedInput, len(inputs))
	for i, field := range inputs {
		value := field["value"]
		attributes := make(map[string]string, len(field))
		for key, value := range field {
			if key != "value" && key != "selector" {
				attributes[key] = value
			}
		}
		prepared[i] = PreparedInput{Attributes: attributes, Value: InputValue(document.Summarize(value))}
		if selector, present := field["selector"]; present {
			prepared[i].Selector = &selector
		}
	}
	return prepared
}

func jsWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	default:
		return r >= 0x2000 && r <= 0x200a
	}
}

func validateActions(actions []Action) error {
	for _, action := range actions {
		if _, raw := action["value"].(string); raw {
			return newError("invalid_actions", "Raw action values are not allowed; use a prepared InputValue")
		}
	}
	return nil
}

// Inputs summarizes values after matching their IDs or names to page controls.
// Password values must instead be summarized explicitly with PrepareInputs.
func (p *Page) Inputs(values map[string]string) ([]PreparedInput, error) {
	doc, err := document.InputDocument(p.html)
	if err != nil {
		return nil, newError("invalid_inputs", err.Error())
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	prepared := make([]PreparedInput, 0, len(keys))
	elements := cascadia.QueryAll(doc, cascadia.MustCompile("*"))
	for _, key := range keys {
		identity := "name"
		for _, node := range elements {
			if value, ok := document.Attribute(node, "id"); ok && value == key {
				identity = "id"
				break
			}
		}
		attributes := map[string]string{identity: key}
		node, err := document.InputNode(doc, attributes, nil)
		if err != nil {
			return nil, newError("invalid_inputs", err.Error())
		}
		if document.PasswordControl(node) {
			return nil, newError("invalid_inputs", "Raw password observations are not allowed")
		}
		prepared = append(prepared, PrepareInputs([]Input{{identity: key, "value": values[key]}})[0])
	}
	return prepared, nil
}

// FwcimInputs binds observations to page controls and prepares their summaries.
// It includes a checksum for nonpassword controls and sends raw text for email
// controls because the collector needs it for canvas rendering. Passwords are
// summarized locally without a checksum or text. Pre-prepared nonpassword
// observations need a checksum when submitted, and email controls need text.
func (p *Page) FwcimInputs(inputs []Input) ([]PreparedInput, error) {
	if inputs == nil {
		return nil, nil
	}
	doc, err := document.InputDocument(p.html)
	if err != nil {
		return nil, newError("invalid_inputs", err.Error())
	}
	result := make([]PreparedInput, 0, len(inputs))
	for _, field := range inputs {
		for name := range field {
			if name != "id" && name != "name" && name != "selector" && name != "value" {
				return nil, newError("invalid_inputs", "Invalid FWCIM input attribute")
			}
		}
		prepared := PrepareInputs([]Input{field})[0]
		_, id := prepared.Attributes["id"]
		_, name := prepared.Attributes["name"]
		if !id && !name && prepared.Selector == nil {
			return nil, newError("invalid_inputs", "FWCIM input requires id, name, or selector")
		}
		node, err := document.InputNode(doc, prepared.Attributes, prepared.Selector)
		if err != nil {
			return nil, newError("invalid_inputs", err.Error())
		}
		if !document.PasswordControl(node) {
			checksum := document.InputChecksum(field["value"])
			prepared.Checksum = &checksum
			kind, _ := document.Attribute(node, "type")
			if strings.EqualFold(strings.TrimSpace(kind), "email") {
				text := field["value"]
				prepared.Text = &text
			}
		}
		result = append(result, prepared)
	}
	return result, nil
}

func (p *Page) prepareInputs(inputs []PreparedInput) ([]PreparedInput, error) {
	doc, err := document.InputDocument(p.html)
	if err != nil {
		return nil, newError("invalid_inputs", err.Error())
	}
	if inputs == nil {
		return nil, nil
	}
	result := make([]PreparedInput, len(inputs))
	for i, input := range inputs {
		if input.Attributes == nil || input.Geometry != nil || input.Checksum != nil || input.Text != nil {
			return nil, newError("invalid_inputs", "Invalid prepared input attributes")
		}
		if _, ok := input.Attributes["value"]; ok {
			return nil, newError("invalid_inputs", "Prepared attributes must not contain raw values")
		}
		if _, ok := input.Attributes["selector"]; ok {
			return nil, newError("invalid_inputs", "Prepared selector must be separate from attributes")
		}
		if input.Selector != nil && strings.TrimSpace(*input.Selector) == "" {
			return nil, newError("invalid_inputs", "Prepared selector must not be empty")
		}
		value := input.Value
		if value.Length < 0 || len(value.Hash) != 64 {
			return nil, newError("invalid_inputs", "Invalid prepared input value")
		}
		for _, char := range value.Hash {
			if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
				return nil, newError("invalid_inputs", "Invalid prepared input hash")
			}
		}
		if value.TrimmedLength != nil && (*value.TrimmedLength < 0 || *value.TrimmedLength > value.Length ||
			(*value.TrimmedLength == 0 && value.TrimmedHash31 != nil && *value.TrimmedHash31 != 0)) {
			return nil, newError("invalid_inputs", "Invalid trimmed input summary")
		}
		if value.Counts != nil {
			counts := *value.Counts
			if counts[0] != value.Length || counts[1] < 0 || counts[2] < 0 || counts[3] < 0 ||
				counts[1] > value.Length-counts[3] || counts[2] > value.Length-counts[3] {
				return nil, newError("invalid_inputs", "Invalid prepared input counts")
			}
			value.Counts = &counts
		}
		_, hasID := input.Attributes["id"]
		_, hasName := input.Attributes["name"]
		if hasID || hasName || input.Selector != nil {
			if _, err := document.InputNode(doc, input.Attributes, input.Selector); err != nil {
				return nil, newError("invalid_inputs", err.Error())
			}
		}
		attributes := make(map[string]string, len(input.Attributes))
		for key, item := range input.Attributes {
			attributes[key] = item
		}
		result[i] = PreparedInput{Attributes: attributes, Value: value}
		if input.Selector != nil {
			selector := *input.Selector
			result[i].Selector = &selector
		}
	}
	return result, nil
}
