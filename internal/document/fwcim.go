package document

import (
	"errors"
	"hash/crc32"
	"unicode/utf16"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// InputChecksum computes CRC32 over the collector's CESU-8 encoding.
func InputChecksum(value string) uint32 {
	crc := uint32(0)
	table := crc32.IEEETable
	var encoded [3]byte
	for _, r := range value {
		units := [2]uint16{uint16(r)}
		count := 1
		if r > 0xffff {
			high, low := utf16.EncodeRune(r)
			units[0], units[1], count = uint16(high), uint16(low), 2
		}
		for _, unit := range units[:count] {
			var n int
			switch {
			case unit < 0x80:
				encoded[0], n = byte(unit), 1
			case unit < 0x800:
				encoded[0], encoded[1], n = 0xc0|byte(unit>>6), 0x80|byte(unit&63), 2
			default:
				encoded[0], encoded[1], encoded[2], n = 0xe0|byte(unit>>12), 0x80|byte(unit>>6&63), 0x80|byte(unit&63), 3
			}
			crc = crc32.Update(crc, table, encoded[:n])
		}
	}
	return crc
}

// FormInput identifies a prepared observation and whether it includes sensitive extras.
type FormInput struct {
	Attributes      map[string]string
	Selector        *string
	SensitiveExtras bool
}

// ValidateForm checks transmitted HTML and binds each observation to a control.
func ValidateForm(source, formSelector string, fields []FormInput) error {
	doc, err := InputDocument(source)
	if err != nil {
		return err
	}
	var form *html.Node
	if formSelector != "" {
		selector, err := cascadia.Compile(formSelector)
		if err != nil {
			return errors.New("nullgate: invalid FWCIM form selector")
		}
		forms := cascadia.QueryAll(doc, selector)
		if len(forms) != 1 || forms[0].Data != "form" {
			return errors.New("nullgate: FWCIM form selector must select exactly one form")
		}
		form = forms[0]
	}
	for _, field := range fields {
		_, hasID := field.Attributes["id"]
		_, hasName := field.Attributes["name"]
		if field.Selector == nil && !hasID && !hasName {
			return errors.New("nullgate: FWCIM input requires id, name, or selector")
		}
		node, err := InputNode(doc, field.Attributes, field.Selector)
		if err != nil {
			return err
		}
		if form != nil {
			parent := node.Parent
			for parent != nil && parent != form {
				parent = parent.Parent
			}
			if parent == nil {
				return errors.New("nullgate: FWCIM input must belong to the selected form")
			}
		}
		if PasswordControl(node) && field.SensitiveExtras {
			return errors.New("nullgate: password text and checksums are not allowed")
		}
	}
	return nil
}
