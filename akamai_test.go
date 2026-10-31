package nullgate_test

import (
	"math"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func TestPrepareInputsUsesUTF16AndNeverRetainsValues(t *testing.T) {
	tests := []struct {
		value                 string
		length                int
		hash                  string
		counts                [4]int
		hash31, trimmedHash31 int32
		trimmedLength         int
	}{
		{"A😀9!", 5, "50c42bbe0b6dd5dc9dd5c42e7b4a7a86ed413e7e808244dfc6f5ba61cb6598d4", [4]int{5, 3, 1, 1}, 1763786604, 1763786604, 5},
		{"İK𝟡\u0085\u2003_", 7, "b1b3376c74a8f446702a82d87339609a5861b7dafa892ed57932df8292e2059d", [4]int{7, 5, 2, 0}, -1249314693, -1249314693, 7},
		{"", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", [4]int{}, 0, 0, 0},
		{"\ufeff\u00a0😀A\u2003B\ufeff", 8, "9ac4389371d08255929fb7ffca33aca69ebeca7a2c8bf6d5c9a0401df498b7df", [4]int{8, 2, 2, 0}, 730619651, 1277143133, 5},
		{"\ufeff\u0085\ufeff", 3, "2da4d1a36bbb068b4931561cfffd548dcb2a7b2958b21f6974adf44ca306f656", [4]int{3, 1, 0, 0}, 62802521, 133, 1},
		{"\x00", 1, "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", [4]int{1, 1, 0, 0}, 0, 0, 1},
		{"\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff", 25, "80876a706847819407472537159f780464b5c125c66616e599da2c5ad02fb632", [4]int{25, 0, 0, 0}, -1202517248, 0, 0},
	}
	fields := make([]nullgate.Input, len(tests))
	for i, test := range tests {
		fields[i] = nullgate.Input{"id": "field", "value": test.value}
	}
	for i, got := range nullgate.PrepareInputs(fields) {
		want := tests[i]
		if got.Value.Length != want.length || got.Value.Hash != want.hash || got.Value.Counts != want.counts {
			t.Errorf("case %d: incorrect UTF-16 digest, length, or character counts", i)
		}
		if got.Value.Hash31 == nil || got.Value.TrimmedHash31 == nil || got.Value.TrimmedLength == nil {
			t.Fatalf("case %d: a computed comparison fact was omitted", i)
		}
		if *got.Value.Hash31 != want.hash31 || *got.Value.TrimmedHash31 != want.trimmedHash31 || *got.Value.TrimmedLength != want.trimmedLength {
			t.Errorf("case %d: incorrect signed UTF-16 hash or ECMAScript trim result", i)
		}
		if _, raw := got.Attributes["value"]; raw {
			t.Errorf("case %d: raw value was retained", i)
		}
		if fields[i]["value"] != want.value {
			t.Errorf("case %d: caller's raw value was mutated", i)
		}
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
