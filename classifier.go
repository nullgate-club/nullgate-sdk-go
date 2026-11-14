package nullgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"mime/multipart"
	"unicode/utf8"
)

// Model selects the classify tier. Match uses its own single model.
type Model string

const (
	Fast     Model = "fast"
	Balanced Model = "balanced"
	Precise  Model = "precise"
)

type ClassifyOptions struct {
	Images [][]byte
	Labels []string
	Model  Model
}
type ClassificationResult struct {
	Label  string    `json:"label"`
	Scores []float64 `json:"scores"`
}
type Classification struct {
	Model   Model                  `json:"model"`
	Results []ClassificationResult `json:"results"`
}
type MatchOptions struct {
	Images  [][]byte
	Queries []string
}
type MatchResult struct {
	Scores []float64 `json:"scores"`
}
type Match struct {
	Results []MatchResult `json:"results"`
}

// JSON null is not a probability. encoding/json otherwise turns it into zero.
type probabilities []float64

func (p *probabilities) UnmarshalJSON(data []byte) error {
	if bytes.Contains(data, []byte("null")) {
		return errors.New("null probability")
	}
	var values []float64
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*p = values
	return nil
}

func (r *ClassificationResult) UnmarshalJSON(data []byte) error {
	var value struct {
		Label  string        `json:"label"`
		Scores probabilities `json:"scores"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	r.Label, r.Scores = value.Label, value.Scores
	return nil
}

func (r *MatchResult) UnmarshalJSON(data []byte) error {
	var value struct {
		Scores probabilities `json:"scores"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	r.Scores = value.Scores
	return nil
}

func imageForm(images [][]byte, text []string, textField string, minimum int, model Model) ([]byte, string, error) {
	if len(images) < 1 || len(images) > 32 {
		return nil, "", newError("invalid_request", "Provide 1 to 32 images")
	}
	if len(text) < minimum || len(text) > 256 {
		return nil, "", newError("invalid_request", "Invalid number of labels or queries")
	}
	total := 0
	for _, image := range images {
		if len(image) == 0 || len(image) > 4<<20 {
			return nil, "", newError("invalid_request", "Each image must contain 1 byte to 4 MiB")
		}
		total += len(image)
	}
	seen := make(map[string]struct{}, len(text))
	for _, value := range text {
		n := utf8.RuneCountInString(value)
		if !utf8.ValidString(value) || n < 1 || n > 256 {
			return nil, "", newError("invalid_request", "Each label or query must contain 1 to 256 characters")
		}
		if _, ok := seen[value]; ok {
			return nil, "", newError("invalid_request", "Labels and queries must be unique")
		}
		seen[value] = struct{}{}
		total += len(value)
	}
	if total > 48<<20 {
		return nil, "", newError("invalid_request", "Classifier body must not exceed 48 MiB")
	}
	var buffer bytes.Buffer
	buffer.Grow(total + 1024)
	writer := multipart.NewWriter(&buffer)
	for _, image := range images {
		part, err := writer.CreateFormFile("image", "image")
		if err != nil {
			return nil, "", err
		}
		if _, err = part.Write(image); err != nil {
			return nil, "", err
		}
	}
	for _, value := range text {
		if err := writer.WriteField(textField, value); err != nil {
			return nil, "", err
		}
	}
	if model != "" {
		if err := writer.WriteField("model", string(model)); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	if buffer.Len() > 48<<20 {
		return nil, "", newError("invalid_request", "Classifier body must not exceed 48 MiB")
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}
func validScores(scores []float64, want int) bool {
	if len(scores) != want {
		return false
	}
	for _, score := range scores {
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return false
		}
	}
	return true
}

// Classify compares candidate labels. Each image is charged once, regardless of label count.
// Images are raw JPEG, PNG, or WebP bytes, transmitted without base64 or gzip.
func (c *Client) Classify(ctx context.Context, options ClassifyOptions) (*Classification, error) {
	if options.Model != "" && options.Model != Fast && options.Model != Balanced && options.Model != Precise {
		return nil, newError("invalid_request", "Unknown classification model")
	}
	body, contentType, err := imageForm(options.Images, options.Labels, "label", 2, options.Model)
	if err != nil {
		return nil, err
	}
	var result Classification
	if err = c.api.Multipart(ctx, "/classifier/classify", contentType, body, &result); err != nil {
		return nil, publicError(err)
	}
	if (result.Model != Fast && result.Model != Balanced && result.Model != Precise) || len(result.Results) != len(options.Images) {
		return nil, protocolError("Malformed classification response")
	}
	for _, row := range result.Results {
		if !validScores(row.Scores, len(options.Labels)) {
			return nil, protocolError("Malformed classification scores")
		}
		found := false
		for _, label := range options.Labels {
			if row.Label == label {
				found = true
				break
			}
		}
		if !found {
			return nil, protocolError("Classification label is not a candidate")
		}
	}
	return &result, nil
}

// Match returns independent scores in query order. Scores do not sum to one.
func (c *Client) Match(ctx context.Context, options MatchOptions) (*Match, error) {
	body, contentType, err := imageForm(options.Images, options.Queries, "query", 1, "")
	if err != nil {
		return nil, err
	}
	var result Match
	if err = c.api.Multipart(ctx, "/classifier/match", contentType, body, &result); err != nil {
		return nil, publicError(err)
	}
	if len(result.Results) != len(options.Images) {
		return nil, protocolError("Malformed match response")
	}
	for _, row := range result.Results {
		if !validScores(row.Scores, len(options.Queries)) {
			return nil, protocolError("Malformed match scores")
		}
	}
	return &result, nil
}
