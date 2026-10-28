package nullgate_test

import (
	"math"
	"reflect"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestPrepareInputsUsesUTF16AndNeverRetainsValues(t *testing.T) {
	fields := []nullgate.Input{
		{"name": "password", "type": "password", "value": "A😀9!"},
		{"id": "unicode", "value": "İK𝟡\u0085\u2003_"},
		{"name": "empty"},
	}
	want := []nullgate.PreparedInput{
		{Attributes: map[string]string{"name": "password", "type": "password"}, Value: nullgate.InputValue{Length: 5, Hash: "50c42bbe0b6dd5dc9dd5c42e7b4a7a86ed413e7e808244dfc6f5ba61cb6598d4", Counts: [4]int{5, 3, 1, 1}}},
		{Attributes: map[string]string{"id": "unicode"}, Value: nullgate.InputValue{Length: 7, Hash: "b1b3376c74a8f446702a82d87339609a5861b7dafa892ed57932df8292e2059d", Counts: [4]int{7, 5, 2, 0}}},
		{Attributes: map[string]string{"name": "empty"}, Value: nullgate.InputValue{Length: 0, Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Counts: [4]int{}}},
	}
	if got := nullgate.PrepareInputs(fields); !reflect.DeepEqual(got, want) {
		t.Errorf("UTF-16 summaries do not match the reference vectors: %#v", got)
	}
	if fields[0]["value"] != "A😀9!" {
		t.Error("PrepareInputs mutated the caller's field")
	}
}

func TestCookieCountersMatchDecimalPrefixesAndURIDecoding(t *testing.T) {
	for _, test := range []struct {
		value             string
		limit, generation float64
	}{
		{"", -1, -1}, {"too~few~parts", -1, -1}, {"x%7E%2B2suffix%7Ey%7E%EF%BB%BF03tail", 2, 3},
		{"x~0~y~9", 0, 9}, {"x~-1~y~4", -1, 4}, {"x~0x10~y~8", 0, 8},
		{"x~+2~y~+8", 2, 8}, {"x~1.5~y~2.9", 1, 2}, {"x~bad~y~3", -1, 3},
		{"x~2~y~%FF", -1, -1}, {"x~2~y~%oops", -1, -1}, {"x~\u00852~y~3", -1, 3},
		{"x~9007199254740993~y~3", 9007199254740992, 3},
	} {
		limit, generation := nullgate.ABCKCounters(test.value)
		if limit != test.limit || generation != test.generation {
			t.Errorf("cookie %q counters=(%v,%v), want (%v,%v)", test.value, limit, generation, test.limit, test.generation)
		}
	}
	if nullgate.IsEnough("", 100) || nullgate.IsEnough("x~-1~y~2", 100) {
		t.Error("unavailable or disabled limit must leave the gate open")
	}
	if nullgate.IsEnough("x~2~y~2", 1) || !nullgate.IsEnough("x~2~y~2", 2) || !nullgate.IsEnough("x~0~y~2", 0) {
		t.Error("ordinary response gate did not respect the observed response limit")
	}
	limit, _ := nullgate.ABCKCounters("x~" + string(makeDigits(400)) + "~y~0")
	if !math.IsInf(limit, 1) {
		t.Error("large decimal prefixes must retain JavaScript Number overflow")
	}
}

func makeDigits(length int) []byte {
	value := make([]byte, length)
	for i := range value {
		value[i] = '9'
	}
	return value
}
