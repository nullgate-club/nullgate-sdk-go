package classifier_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ng "github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/classifier"
)

// A missing measurement must not become an apparently certain zero probability.
func TestClassifierRejectsMissingOrMalformedScores(t *testing.T) {
	for _, scores := range []string{`[null,1]`, `null`, `["0",1]`, `[0,1,0]`, `[-0.1,1.1]`} {
		t.Run(scores, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseMultipartForm(4096); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				defer r.MultipartForm.RemoveAll()
				if r.Header.Get("Content-Encoding") != "" {
					t.Error("image multipart must not be gzipped")
				}
				io.WriteString(w, `{"model":"balanced","results":[{"label":"dog","scores":`+scores+`}]}`)
			}))
			defer api.Close()
			client, err := ng.New("ng_test", ng.Options{BaseURL: api.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, err = classifier.New(client).Classify(context.Background(), classifier.ClassifyOptions{Images: [][]byte{[]byte("image")}, Labels: []string{"cat", "dog"}})
			var failure *ng.Error
			if !errors.As(err, &failure) || failure.Code != "protocol_error" {
				t.Fatalf("classify accepted malformed scores: %v", err)
			}
			_, err = classifier.New(client).Match(context.Background(), classifier.MatchOptions{Images: [][]byte{[]byte("image")}, Queries: []string{"cat", "dog"}})
			if !errors.As(err, &failure) || failure.Code != "protocol_error" {
				t.Fatalf("match accepted malformed scores: %v", err)
			}
		})
	}
}
