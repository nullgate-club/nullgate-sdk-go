package nullgate

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AbckCounters returns the response limit and cookie generation when both are available.
func AbckCounters(value string) (limit, generation int, ok bool) {
	limit, generation, limitOK, generationOK := cookieCounters(value)
	return limit, generation, limitOK && generationOK
}

func cookieCounters(value string) (int, int, bool, bool) {
	decoded, err := url.PathUnescape(value)
	if err != nil || !utf8.ValidString(decoded) {
		return -1, -1, false, false
	}
	parts := strings.Split(decoded, "~")
	if len(parts) < 4 {
		return -1, -1, false, false
	}
	limit, a := counterPrefix(parts[1])
	generation, b := counterPrefix(parts[3])
	return limit, generation, a, b
}

// IsEnough checks ordinary sensor-send eligibility, not target acceptance.
func IsEnough(value string, responseCount int) bool {
	limit, _, ok, _ := cookieCounters(value)
	return ok && limit != -1 && responseCount >= limit
}

func counterPrefix(value string) (int, bool) {
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
		return -1, false
	}
	result, err := strconv.Atoi(value[:end])
	if err != nil {
		return -1, false
	}
	return result, true
}

// CookiesFromJar reads cookies for a target URL without making a request.
func CookiesFromJar(jar http.CookieJar, address string) (map[string]string, error) {
	u, err := absoluteHTTPURL(address)
	if err != nil {
		return nil, newError("invalid_url", "cookie URL must be an absolute HTTP(S) URL")
	}
	result := make(map[string]string)
	if jar != nil {
		for _, cookie := range jar.Cookies(u) {
			result[cookie.Name] = cookie.Value
		}
	}
	return result, nil
}
