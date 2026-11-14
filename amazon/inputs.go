package amazon

import (
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/internal/document"
	"strings"
)

func PrepareInputs(p *browser.Page, inputs []browser.Input) ([]Input, error) {
	if inputs == nil {
		return nil, nil
	}
	doc, err := document.InputDocument(p.HTML())
	if err != nil {
		return nil, api.NewError("invalid_inputs", err.Error())
	}
	result := make([]Input, 0, len(inputs))
	for _, field := range inputs {
		for name := range field {
			if name != "id" && name != "name" && name != "selector" && name != "value" {
				return nil, api.NewError("invalid_inputs", "Invalid FWCIM input attribute")
			}
		}
		prepared := Input{PreparedInput: browser.PrepareInputs([]browser.Input{field})[0]}
		_, id := prepared.Attributes["id"]
		_, name := prepared.Attributes["name"]
		if !id && !name && prepared.Selector == nil {
			return nil, api.NewError("invalid_inputs", "FWCIM input requires id, name, or selector")
		}
		node, err := document.InputNode(doc, prepared.Attributes, prepared.Selector)
		if err != nil {
			return nil, api.NewError("invalid_inputs", err.Error())
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
