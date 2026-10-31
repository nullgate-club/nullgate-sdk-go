package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/google/uuid"
	nullgate "github.com/nullgate-club/nullgate-sdk-go"
	"golang.org/x/net/publicsuffix"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	pageURL, key, proxyURL := os.Getenv("TARGET_URL"), os.Getenv("NULLGATE_API_KEY"), os.Getenv("TARGET_PROXY")
	if pageURL == "" || key == "" {
		return errors.New("set TARGET_URL and NULLGATE_API_KEY; TARGET_PROXY empty explicitly selects direct")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return err
	}
	browser := &http.Client{Transport: transport, Jar: jar}
	// The standard provider's native jar is caller-owned. A per-request client
	// copy with no jar neither sends nor retains cookies for credentials=omit.
	fetch := func(ctx context.Context, input nullgate.TargetRequest) (nullgate.TargetResponse, error) {
		var bodyReader io.Reader
		if input.Body != nil {
			bodyReader = bytes.NewReader(input.Body)
		}
		request, err := http.NewRequestWithContext(ctx, input.Method, input.URL, bodyReader)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		request.GetBody = nil
		for name, value := range input.Headers {
			request.Header.Set(name, value)
		}
		perRequest := *browser
		if input.Credentials == nullgate.CredentialsOmit {
			perRequest.Jar = nil
			request.Header.Del("Cookie")
		}
		response, err := perRequest.Do(request)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nullgate.TargetResponse{}, err
		}
		headers := make(map[string]string, len(response.Header))
		for name, values := range response.Header {
			headers[name] = strings.Join(values, ", ")
		}
		return nullgate.TargetResponse{Status: response.StatusCode, Headers: headers, Body: body}, nil
	}
	target, err := nullgate.NewTarget(fetch, proxyURL)
	if err != nil {
		return err
	}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return errors.New("invalid target proxy")
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return errors.New("invalid TARGET_URL")
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := browser.Do(request)
	if err != nil {
		return errors.New("target page request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return errors.New("target page response failed")
	}
	found, err := nullgate.FindProtections(nullgate.Page{URL: response.Request.URL.String(), HTML: string(body)})
	if err != nil {
		return err
	}
	if len(found) != 1 {
		return errors.New("expected one ThreatMetrix tags script in the target page")
	}
	protection, ok := found[0].(nullgate.ThreatMetrix)
	if !ok {
		return errors.New("the discovered protection is not ThreatMetrix; use the target example for Akamai")
	}
	client, err := nullgate.NewClient(key, nullgate.Options{ProfileBaseURL: os.Getenv("NULLGATE_PROFILE_BASE_URL")})
	if err != nil {
		return err
	}
	defer client.Close()
	identity := os.Getenv("NULLGATE_IDENTITY")
	if identity == "" {
		identity = uuid.NewString()
	}
	session, err := client.Open(nullgate.SessionOptions{Identity: identity, UserAgent: userAgent})
	if err != nil {
		return err
	}
	defer session.Close()
	profile, err := session.Profile(ctx, nullgate.ThreatMetrixParams{Protection: protection}, target)
	if err != nil {
		return err
	}
	defer profile.Close()
	fmt.Printf("Profiling startup delivered (request_id=%s); target acceptance is not established.\n", profile.RequestID)
	// Real applications keep the handle alive while the document is active.
	// This short example explicitly leaves the document immediately after ready.
	if err := profile.Pagehide(ctx, nil, false); err != nil {
		return err
	}
	return profile.WaitCollected(ctx)
}
