package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func main() {
	ctx := context.Background()
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	withCookies := &http.Client{Jar: jar}
	withoutCookies := &http.Client{}
	send := func(ctx context.Context, request nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, nil)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		if request.Body != nil {
			req.Body = io.NopCloser(bytes.NewReader(request.Body))
			req.ContentLength = int64(len(request.Body))
		}
		for name, value := range request.Headers {
			req.Header.Set(name, value)
		}
		client := withCookies
		if request.Credentials == nullgate.CredentialsOmit {
			client = withoutCookies
		}
		resp, err := client.Do(req)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		headers := make(map[string]string)
		for name, values := range resp.Header {
			if len(values) > 0 {
				headers[name] = values[0]
			}
		}
		return nullgate.TargetResponse{Status: resp.StatusCode, Headers: headers, Body: body}, nil
	}
	client, err := nullgate.NewClient("", nullgate.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	session, err := client.Session(nullgate.SessionOptions{UserAgent: os.Getenv("USER_AGENT")})
	if err != nil {
		log.Fatal(err)
	}
	html, err := os.ReadFile(os.Getenv("PAGE_HTML"))
	if err != nil {
		log.Fatal(err)
	}
	page, err := session.Page(os.Getenv("PAGE_URL"), string(html), nullgate.PageOptions{})
	if err != nil {
		log.Fatal(err)
	}
	profile, err := page.ThreatMetrix(ctx, nullgate.ThreatMetrixOptions{Send: send, ScriptURL: os.Getenv("TAGS_URL")})
	if err != nil {
		log.Fatal(err)
	}
	defer profile.Close()
	if err = profile.WaitCollected(ctx); err != nil {
		log.Fatal(err)
	}
	if err = profile.Pagehide(ctx, nil, false); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Profile collected and departure acknowledged")
}
