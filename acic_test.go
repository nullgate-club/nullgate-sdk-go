package nullgate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func TestAcicErrorsDoNotRepeatBilledRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"maintenance","message":"down","request_id":"r"}`))
	}))
	defer server.Close()
	client, err := nullgate.NewClient("ng_test", nullgate.Options{BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.AcicPow(context.Background(), nullgate.AcicPowOptions{ChallengeType: "POW", HTML: "page"})
	var apiErr *nullgate.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "maintenance" || calls != 1 {
		t.Fatalf("error %v, requests %d", err, calls)
	}
}
func TestAcicWafVerificationBodyPreservesProblem(t *testing.T) {
	r := nullgate.AcicWafResult{ClientSolution: []int{1, 3}}
	body, err := r.VerificationBody(json.RawMessage(`{"state":{"n":9007199254740993},"key":"k","hmac_tag":"h"}`), 1.2349, "en")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		State   json.RawMessage `json:"state"`
		Metrics struct {
			Time int `json:"solve_time_millis"`
		} `json:"metrics"`
		Solution []int `json:"client_solution"`
	}
	if err = json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.State) != `{"n":9007199254740993}` || got.Metrics.Time != 1234 || len(got.Solution) != 2 || got.Solution[1] != 3 {
		t.Fatalf("incorrect verification body: %s", body)
	}
}
