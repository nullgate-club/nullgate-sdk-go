package nullgate

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type websitePayload struct {
	URL         string `json:"url"`
	HTML        string `json:"html"`
	DocumentID  string `json:"document_id"`
	StartedAtMS int64  `json:"started_at_ms"`
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

func observePage(page Page, previous websitePayload) (websitePayload, error) {
	if err := validatePage(page); err != nil {
		return websitePayload{}, err
	}
	observed := websitePayload{URL: page.URL, HTML: page.HTML}
	if page.DocumentID != "" {
		observed.DocumentID, observed.StartedAtMS = page.DocumentID, *page.StartedAtMS
	} else if previous.DocumentID != "" && previous.URL == page.URL && previous.HTML == page.HTML {
		observed.DocumentID, observed.StartedAtMS = previous.DocumentID, previous.StartedAtMS
	} else {
		id, err := uuid.NewRandom()
		if err != nil {
			return websitePayload{}, errors.New("nullgate: could not create document observation")
		}
		observed.DocumentID, observed.StartedAtMS = id.String(), time.Now().UnixMilli()
	}
	return observed, nil
}

func generationPayload(params Params, timezone *string, previous websitePayload) (operation string, payload generatePayload, target string, err error) {
	var page Page
	payload.Timezone = timezone
	switch p := params.(type) {
	case *PixelParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: PixelParams must not be nil")
		}
		return generationPayload(*p, timezone, previous)
	case *SensorParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: SensorParams must not be nil")
		}
		return generationPayload(*p, timezone, previous)
	case *SbsdParams:
		if p == nil {
			return "", payload, "", errors.New("nullgate: SbsdParams must not be nil")
		}
		return generationPayload(*p, timezone, previous)
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
			if err := validateActions(p.Actions); err != nil {
				return "", payload, "", err
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
	if _, err := absoluteHTTPURL(target); err != nil {
		return "", payload, "", errors.New("nullgate: Protection.ScriptURL must be an absolute HTTP(S) URL")
	}
	if payload.Script.Text == "" {
		return "", payload, "", errors.New("nullgate: Script must contain the source text")
	}
	payload.Website, err = observePage(page, previous)
	if err != nil {
		return "", payload, "", err
	}
	payload.Script.Source = target
	return operation, payload, target, nil
}
