package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
	nullgate "github.com/nullgate-club/nullgate-sdk-go"
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
	targetURL, key := os.Getenv("TARGET_URL"), os.Getenv("NULLGATE_API_KEY")
	if targetURL == "" || key == "" {
		return errors.New("set TARGET_URL and NULLGATE_API_KEY")
	}
	identity := os.Getenv("NULLGATE_IDENTITY")
	if identity == "" {
		identity = uuid.NewString()
	}
	target, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithTimeoutSeconds(30),
	)
	if err != nil {
		return err
	}
	defer target.CloseIdleConnections()

	headers := http.Header{
		"User-Agent":      {userAgent},
		"Accept-Language": {"en-US,en;q=0.9"},
	}
	pageRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	pageRequest.Header = headers.Clone()
	pageRequest.Header["accept"] = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"}
	pageResponse, err := target.Do(pageRequest)
	if err != nil {
		return err
	}
	defer pageResponse.Body.Close()
	html, err := io.ReadAll(pageResponse.Body)
	if err != nil {
		return err
	}
	page := nullgate.Page{URL: pageResponse.Request.URL.String(), HTML: string(html)}
	protections, err := nullgate.FindProtections(page)
	if err != nil {
		return err
	}
	if len(protections) == 0 {
		fmt.Printf("Target page HTTP %d; no supported protection discovered.\n", pageResponse.StatusCode)
		return nil
	}
	var scriptURL string
	switch p := protections[0].(type) {
	case nullgate.Sensor:
		scriptURL = p.ScriptURL
	case nullgate.Pixel:
		scriptURL = p.ScriptURL
	case nullgate.Sbsd:
		scriptURL = p.ScriptURL
	default:
		return fmt.Errorf("unsupported protection type %T", protections[0])
	}

	scriptRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return err
	}
	scriptRequest.Header = headers.Clone()
	scriptRequest.Header["accept"] = []string{"*/*"}
	scriptRequest.Header["referer"] = []string{page.URL}
	scriptResponse, err := target.Do(scriptRequest)
	if err != nil {
		return err
	}
	defer scriptResponse.Body.Close()
	if scriptResponse.StatusCode < 200 || scriptResponse.StatusCode >= 300 {
		return fmt.Errorf("target script HTTP %d", scriptResponse.StatusCode)
	}
	script, err := io.ReadAll(scriptResponse.Body)
	if err != nil {
		return err
	}
	cookies := make(map[string]string)
	for _, cookie := range target.GetCookies(pageResponse.Request.URL) {
		if !cookie.HttpOnly {
			cookies[cookie.Name] = cookie.Value
		}
	}
	var params nullgate.Params
	switch p := protections[0].(type) {
	case nullgate.Sensor:
		params = nullgate.SensorParams{Protection: p, Script: string(script), Cookies: cookies}
	case nullgate.Pixel:
		params = nullgate.PixelParams{Protection: p, Script: string(script)}
	case nullgate.Sbsd:
		params = nullgate.SbsdParams{Protection: p, Script: string(script), Cookies: cookies}
	}

	api, err := nullgate.NewClient(key, nullgate.Options{
		BaseURL: os.Getenv("NULLGATE_BASE_URL"), AnalyticsURL: os.Getenv("ANALYTICS_URL"),
	})
	if err != nil {
		return err
	}
	defer api.Close()
	session, err := api.Open(nullgate.SessionOptions{Identity: identity, UserAgent: userAgent})
	if err != nil {
		return err
	}
	defer session.Close()
	solution, err := session.Solve(ctx, params)
	if err != nil {
		return err
	}
	if err := solution.Wait(ctx); err != nil {
		return err
	}

	post, err := http.NewRequestWithContext(ctx, solution.Method, solution.URL, strings.NewReader(solution.Body))
	if err != nil {
		return err
	}
	post.Header = headers.Clone()
	post.Header["accept"] = []string{"*/*"}
	post.Header["origin"] = []string{pageResponse.Request.URL.Scheme + "://" + pageResponse.Request.URL.Host}
	post.Header["referer"] = []string{page.URL}
	for name, value := range solution.Headers {
		post.Header[strings.ToLower(name)] = []string{value}
	}
	target.SetFollowRedirect(false)
	response, err := target.Do(post)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Target POST HTTP %d (request_id=%s)\n%s\n", response.StatusCode, solution.RequestID, body)
	return nil
}
