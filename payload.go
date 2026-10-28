package nullgate

import "errors"

type websitePayload struct {
	URL  string `json:"url"`
	HTML string `json:"html"`
}

type scriptPayload struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type generatePayload struct {
	Website   websitePayload     `json:"website"`
	Script    scriptPayload      `json:"script"`
	Timezone  *string            `json:"timezone,omitempty"`
	Challenge string             `json:"challenge,omitempty"`
	Cookies   *map[string]string `json:"cookies,omitempty"`
	Inputs    *[]PreparedInput   `json:"inputs,omitempty"`
	Actions   *[]Action          `json:"actions,omitempty"`
}

func generationPayload(params Params, timezone *string) (operation string, payload generatePayload, target string, err error) {
	var page Page
	payload.Timezone = timezone
	switch p := params.(type) {
	case *PixelParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: PixelParams must not be nil")
		}
		return generationPayload(*p, timezone)
	case *SensorParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: SensorParams must not be nil")
		}
		return generationPayload(*p, timezone)
	case *SbsdParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: SbsdParams must not be nil")
		}
		return generationPayload(*p, timezone)
	case PixelParams:
		operation, page, target = "pixel", p.Protection.Page, p.Protection.ScriptURL
		payload.Script.Text, payload.Challenge = p.Script, p.Protection.Challenge
		if payload.Challenge == "" {
			return "", payload, "", errors.New("nullgate: Pixel.Challenge must contain decimal digits")
		}
		for _, r := range payload.Challenge {
			if r < '0' || r > '9' {
				return "", payload, "", errors.New("nullgate: Pixel.Challenge must contain decimal digits")
			}
		}
	case SensorParams:
		operation, page, target = "akamai", p.Protection.Page, p.Protection.ScriptURL
		payload.Script.Text = p.Script
		cookies := p.Cookies
		if cookies == nil {
			cookies = map[string]string{}
		}
		payload.Cookies = &cookies
		if p.Inputs != nil {
			inputs := PrepareInputs(p.Inputs)
			payload.Inputs = &inputs
		}
		if p.Actions != nil {
			for _, action := range p.Actions {
				if action["type"] == "input" || action["type"] == "change" {
					if _, raw := action["value"].(string); raw {
						return "", payload, "", errors.New("nullgate: input/change action values must be prepared InputValue summaries, not raw strings")
					}
				}
			}
			payload.Actions = &p.Actions
		}
	case SbsdParams:
		operation, page, target = "sbsd", p.Protection.Page, p.Protection.ScriptURL
		payload.Script.Text = p.Script
		cookies := p.Cookies
		if cookies == nil {
			cookies = map[string]string{}
		}
		payload.Cookies = &cookies
	default:
		return "", payload, "", errors.New("nullgate: Solve requires PixelParams, SensorParams, or SbsdParams")
	}
	if err := validatePage(page); err != nil {
		return "", payload, "", err
	}
	if _, err := absoluteHTTPURL(target); err != nil {
		return "", payload, "", errors.New("nullgate: Protection.ScriptURL must be an absolute HTTP(S) URL")
	}
	if payload.Script.Text == "" {
		return "", payload, "", errors.New("nullgate: Script must contain the source text")
	}
	payload.Website = websitePayload{URL: page.URL, HTML: page.HTML}
	payload.Script.Source = target
	return operation, payload, target, nil
}
