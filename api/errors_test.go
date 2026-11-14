package api_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
)

// Ordinary error logging must reveal the safe failure reason, not an underlying credential.
func TestErrorFormattingRetainsReasonWithoutCause(t *testing.T) {
	_, badKey := api.New("invalid", api.Options{})
	_, badTimeout := api.New("ng_test", api.Options{Timeout: -time.Second})
	for _, failure := range []error{badKey, badTimeout, &api.Error{Code: "transport_error", Message: "API connection failed", Cause: fmt.Errorf("Authorization: Bearer ng_private")}} {
		detail, ok := failure.(*api.Error)
		if !ok {
			t.Fatalf("expected API error, got %T", failure)
		}
		for _, rendered := range []string{fmt.Sprintf("%v", failure), fmt.Sprintf("%#v", failure)} {
			if detail.Message == "" || !strings.Contains(rendered, detail.Message) {
				t.Fatalf("safe failure reason disappeared: %q", rendered)
			}
			if strings.Contains(rendered, "ng_private") || strings.Contains(rendered, "Authorization") {
				t.Fatal("error formatter disclosed the underlying credential")
			}
		}
	}
}
