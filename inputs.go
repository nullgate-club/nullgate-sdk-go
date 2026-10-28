package nullgate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"unicode"
	"unicode/utf16"
)

// InputValue is a privacy-preserving UTF-16 summary, matching JavaScript field
// lengths. Counts are total code units, special code units, ASCII letters after
// lowercasing, and ASCII digits, respectively.
type InputValue struct {
	Length int    `json:"length"`
	Hash   string `json:"hash"`
	Counts [4]int `json:"counts"`
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
		for _, r := range value {
			units := 1
			if r > 0xffff {
				high, low := utf16.EncodeRune(r)
				encoded = binary.LittleEndian.AppendUint16(encoded, uint16(high))
				encoded = binary.LittleEndian.AppendUint16(encoded, uint16(low))
				units = 2
			} else {
				encoded = binary.LittleEndian.AppendUint16(encoded, uint16(r))
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
			Value:      InputValue{Length: counts[0], Hash: hex.EncodeToString(digest[:]), Counts: counts},
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
