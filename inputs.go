package nullgate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"unicode"
	"unicode/utf16"
)

// InputValue is a privacy-preserving UTF-16 summary, matching JavaScript field
// lengths. Counts are total code units, special code units, ASCII letters after
// lowercasing, and ASCII digits, respectively. Optional comparison facts use
// pointers so that a computed zero is distinct from an absent observation.
type InputValue struct {
	Length        int    `json:"length"`
	Hash          string `json:"hash"`
	Counts        [4]int `json:"counts"`
	Hash31        *int32 `json:"hash31,omitempty"`
	TrimmedHash31 *int32 `json:"trimmed_hash31,omitempty"`
	TrimmedLength *int   `json:"trimmed_length,omitempty"`
}

// PreparedInput retains attributes but never a raw field value.
type PreparedInput struct {
	Attributes map[string]string `json:"attributes"`
	Value      InputValue        `json:"value"`
}

// PrepareInputs hashes UTF-16LE bytes locally, preserving field order and all
// attributes except value. It does not mutate its argument.
func PrepareInputs(inputs []Input) []PreparedInput {
	prepared := make([]PreparedInput, len(inputs))
	for i, field := range inputs {
		value := field["value"]
		encoded := make([]byte, 0, len(value)*2)
		counts := [4]int{}
		comparison := struct {
			raw, trimmed int32
			length       int
		}{}
		var trimmedHash int32
		trimmedLength := 0
		trimStarted := false
		appendUnit := func(unit uint16) {
			encoded = binary.LittleEndian.AppendUint16(encoded, unit)
			comparison.raw = 31*comparison.raw + int32(unit)
			if trimStarted {
				trimmedHash = 31*trimmedHash + int32(unit)
				trimmedLength++
			}
		}
		for _, r := range value {
			whitespace := jsWhitespace(r)
			if !whitespace {
				trimStarted = true
			}
			units := 1
			if r > 0xffff {
				high, low := utf16.EncodeRune(r)
				appendUnit(uint16(high))
				appendUnit(uint16(low))
				units = 2
			} else {
				appendUnit(uint16(r))
			}
			if !whitespace {
				comparison.trimmed = trimmedHash
				comparison.length = trimmedLength
			}
			counts[0] += units
			if !nonSpecial(r) {
				counts[1] += units
			}
			lower := unicode.ToLower(r)
			if lower >= 'a' && lower <= 'z' {
				counts[2]++
			}
			if r >= '0' && r <= '9' {
				counts[3]++
			}
		}
		attributes := make(map[string]string, len(field))
		for key, value := range field {
			if key != "value" {
				attributes[key] = value
			}
		}
		digest := sha256.Sum256(encoded)
		prepared[i] = PreparedInput{
			Attributes: attributes,
			Value: InputValue{
				Length: counts[0], Hash: hex.EncodeToString(digest[:]), Counts: counts,
				Hash31: &comparison.raw, TrimmedHash31: &comparison.trimmed,
				TrimmedLength: &comparison.length,
			},
		}
	}
	return prepared
}

func nonSpecial(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || jsWhitespace(r)
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
		if action["type"] == "input" || action["type"] == "change" {
			if _, raw := action["value"].(string); raw {
				return errors.New("nullgate: input/change action values must be prepared InputValue summaries, not raw strings")
			}
		}
	}
	return nil
}
