package nullgate

import (
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ABCKCounters returns the ordinary-response limit and cookie generation. An
// unavailable counter is -1. This mirrors JavaScript's decimal parseInt prefix
// and Number rounding, not a website-acceptance decision.
func ABCKCounters(value string) (limit, generation float64) {
	decoded, err := url.PathUnescape(value)
	if err != nil || !utf8.ValidString(decoded) {
		return -1, -1
	}
	var parts [4]string
	remaining := decoded
	for i := range 3 {
		var found bool
		parts[i], remaining, found = strings.Cut(remaining, "~")
		if !found {
			return -1, -1
		}
	}
	parts[3], _, _ = strings.Cut(remaining, "~")
	return counterPrefix(parts[1]), counterPrefix(parts[3])
}

// IsEnough checks only ordinary sensor-send eligibility. responseCount is the
// number of completed target sensor responses in the current cookie generation.
func IsEnough(value string, responseCount int) bool {
	limit, _ := ABCKCounters(value)
	return limit != -1 && float64(responseCount) >= limit
}

func counterPrefix(value string) float64 {
	value = strings.TrimLeftFunc(value, jsWhitespace)
	end := 0
	if len(value) > 0 && (value[0] == '+' || value[0] == '-') {
		end++
	}
	start := end
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == start {
		return -1
	}
	result, err := strconv.ParseFloat(value[:end], 64)
	if err != nil {
		if numberError, ok := err.(*strconv.NumError); !ok || numberError.Err != strconv.ErrRange {
			return -1
		}
	}
	return result
}
