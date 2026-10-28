package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
	nullgate "github.com/nullgate-club/nullgate-sdk-go"
	"golang.org/x/net/publicsuffix"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
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
	jar, err := newDocumentCookies()
	if err != nil {
		return err
	}
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithTimeoutSeconds(30),
		tlsclient.WithCustomRedirectFunc(func(_ *http.Request, via []*http.Request) error {
			// Navigation/script GETs may redirect; generated POSTs never do.
			if len(via) >= 10 || (len(via) > 0 && via[0].Method != http.MethodGet) {
				return http.ErrUseLastResponse
			}
			return nil
		}),
	}
	if proxy := os.Getenv("TARGET_PROXY"); proxy != "" {
		options = append(options, tlsclient.WithProxyUrl(proxy))
	}
	target, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return errors.New("cannot configure Chrome 146 target transport; check TARGET_PROXY")
	}
	defer target.CloseIdleConnections()
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
	page, status, err := getPage(ctx, target, targetURL)
	if err != nil {
		return err
	}
	for range 4 {
		protections, err := nullgate.FindProtections(page)
		if err != nil {
			return err
		}
		var pixel *nullgate.Pixel
		var sensor *nullgate.Sensor
		var sbsd *nullgate.Sbsd
		for _, candidate := range protections {
			switch p := candidate.(type) {
			case nullgate.Pixel:
				if pixel != nil {
					return errors.New("ambiguous pixel scripts/challenges; select the intended candidate explicitly")
				}
				pixel = &p
			case nullgate.Sensor:
				if sensor != nil {
					return errors.New("ambiguous sensor candidates; select the intended script explicitly")
				}
				sensor = &p
			case nullgate.Sbsd:
				if sbsd != nil {
					return errors.New("ambiguous SBSD candidates; select the intended script explicitly")
				}
				sbsd = &p
			}
		}
		if len(protections) == 0 {
			return fmt.Errorf("target HTTP %d has no supported protection candidates", status)
		}
		var last *nullgate.Solution
		if sbsd != nil {
			script, err := getScript(ctx, target, sbsd.ScriptURL, page.URL)
			if err != nil {
				return err
			}
			last, err = submit(ctx, target, session, nullgate.SbsdParams{Protection: *sbsd, Script: script, Cookies: cookies(jar, page.URL)}, page.URL)
			if err != nil {
				return err
			}
			if sbsd.Blocking() {
				// A POST 200 is not clearance: revisit the original navigation.
				page, status, err = getPage(ctx, target, targetURL)
				if err != nil {
					return err
				}
				after, err := nullgate.FindProtections(page)
				if err != nil {
					return err
				}
				for _, candidate := range after {
					if p, ok := candidate.(nullgate.Sbsd); ok && p.Blocking() {
						return rejected(ctx, last, "blocking SBSD remains after original-page re-fetch")
					}
				}
				if status < 200 || status >= 300 {
					return rejected(ctx, last, fmt.Sprintf("original-page re-fetch returned HTTP %d", status))
				}
				if len(after) == 0 {
					fmt.Printf("Original page HTTP %d, blocking SBSD no longer discovered; verify the intended target content.\n", status)
					return nil
				}
				session.Close()
				session, err = api.Open(nullgate.SessionOptions{Identity: identity, UserAgent: userAgent})
				if err != nil {
					return err
				}
				defer session.Close()
				continue
			}
		}
		if pixel != nil {
			script, err := getScript(ctx, target, pixel.ScriptURL, page.URL)
			if err != nil {
				return err
			}
			last, err = submit(ctx, target, session, nullgate.PixelParams{Protection: *pixel, Script: script}, page.URL)
			if err != nil {
				return err
			}
		}
		if sensor != nil {
			script, err := getScript(ctx, target, sensor.ScriptURL, page.URL)
			if err != nil {
				return err
			}
			responses, previousGeneration := 0, float64(-1)
			for sent := 0; ; sent++ {
				current := cookies(jar, page.URL)
				for name := range current {
					if name != "_abck" && name != "bm_sz" {
						delete(current, name)
					}
				}
				_, generation := nullgate.ABCKCounters(current["_abck"])
				if generation >= 0 && generation != previousGeneration {
					responses, previousGeneration = 0, generation
				}
				if nullgate.IsEnough(current["_abck"], responses) {
					break
				}
				if sent >= 4 {
					return errors.New("diagnostic stop: cookie gate still open after four sensor responses; no acceptance inferred")
				}
				last, err = submit(ctx, target, session, nullgate.SensorParams{Protection: *sensor, Script: script, Cookies: current}, page.URL)
				if err != nil {
					return err
				}
				responses++
			}
			fmt.Println("Ordinary sensor cookie gate closed; this is not proof of target acceptance.")
		}
		final, finalStatus, err := getPage(ctx, target, targetURL)
		if err != nil {
			return err
		}
		if finalStatus < 200 || finalStatus >= 300 {
			return rejected(ctx, last, fmt.Sprintf("original-page re-fetch returned HTTP %d", finalStatus))
		}
		after, err := nullgate.FindProtections(final)
		if err != nil {
			return err
		}
		for _, candidate := range after {
			if p, ok := candidate.(nullgate.Sbsd); ok && p.Blocking() {
				return rejected(ctx, last, "original page remains a blocking SBSD challenge")
			}
		}
		fmt.Printf("Original page HTTP %d; verify intended content. HTTP 200 alone is not acceptance.\n", finalStatus)
		return nil
	}
	return errors.New("diagnostic stop: repeated document transitions; no acceptance inferred")
}

func targetRequest(ctx context.Context, target tlsclient.HttpClient, method, endpoint, body, referer, destination string, extra map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid target URL")
	}
	req.Header = http.Header{
		"sec-ch-ua":        {`"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="99"`},
		"sec-ch-ua-mobile": {"?0"}, "sec-ch-ua-platform": {`"Windows"`},
		"user-agent": {userAgent}, "accept": {"*/*"}, "accept-language": {"en-US,en;q=0.9"},
		"sec-fetch-site": {"same-origin"}, "sec-fetch-mode": {"cors"}, "sec-fetch-dest": {destination},
		http.HeaderOrderKey: {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "content-type", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie"},
	}
	if destination == "document" {
		req.Header["accept"] = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"}
		req.Header["sec-fetch-site"] = []string{"none"}
		req.Header["sec-fetch-mode"] = []string{"navigate"}
		req.Header["sec-fetch-user"] = []string{"?1"}
		req.Header["upgrade-insecure-requests"] = []string{"1"}
	} else if destination == "script" {
		req.Header["sec-fetch-mode"] = []string{"no-cors"}
	}
	if referer != "" {
		req.Header["referer"] = []string{referer}
		if method == http.MethodPost {
			u, err := url.Parse(referer)
			if err != nil {
				return nil, errors.New("invalid page URL")
			}
			req.Header["origin"] = []string{u.Scheme + "://" + u.Host}
		}
	}
	for name, value := range extra {
		req.Header[strings.ToLower(name)] = []string{value}
	}
	return target.Do(req)
}

func getPage(ctx context.Context, target tlsclient.HttpClient, endpoint string) (nullgate.Page, int, error) {
	resp, err := targetRequest(ctx, target, http.MethodGet, endpoint, "", "", "document", nil)
	if err != nil {
		return nullgate.Page{}, 0, errors.New("target navigation failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return nullgate.Page{URL: resp.Request.URL.String(), HTML: string(body)}, resp.StatusCode, err
}

func getScript(ctx context.Context, target tlsclient.HttpClient, endpoint, referer string) (string, error) {
	resp, err := targetRequest(ctx, target, http.MethodGet, endpoint, "", referer, "script", nil)
	if err != nil {
		return "", errors.New("target script fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("target script HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func submit(ctx context.Context, target tlsclient.HttpClient, session *nullgate.Session, params nullgate.Params, referer string) (*nullgate.Solution, error) {
	solution, err := session.Solve(ctx, params)
	if err != nil {
		return nil, err
	}
	if err := solution.Wait(ctx); err != nil {
		return nil, err
	}
	resp, err := targetRequest(ctx, target, solution.Method, solution.URL, solution.Body, referer, "empty", solution.Headers)
	if err != nil {
		return nil, errors.New("target submission failed; generation was not retried")
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, err
	}
	fmt.Printf("Generated POST: target HTTP %d (request_id=%s)\n", resp.StatusCode, solution.RequestID)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, rejected(ctx, solution, fmt.Sprintf("target POST returned HTTP %d; this is a user signal, not proof of payload failure", resp.StatusCode))
	}
	return solution, nil
}

func cookies(jar *documentCookies, endpoint string) map[string]string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return map[string]string{}
	}
	values := make(map[string]string)
	for _, cookie := range jar.visible.Cookies(u) {
		values[cookie.Name] = cookie.Value
	}
	return values
}

func rejected(ctx context.Context, solution *nullgate.Solution, reason string) error {
	if solution == nil {
		return errors.New(reason)
	}
	delivered, err := solution.Report(ctx)
	if err != nil {
		return fmt.Errorf("%s; report failed: %w", reason, err)
	}
	return fmt.Errorf("%s; report HTTP delivery=%t (no refund or archive-acceptance claim)", reason, delivered)
}

// Both projections use the maintained RFC cookie jar; document.cookie excludes HttpOnly.
type documentCookies struct {
	network *cookiejar.Jar
	visible *cookiejar.Jar
}

func newDocumentCookies() (*documentCookies, error) {
	options := &cookiejar.Options{PublicSuffixList: publicsuffix.List}
	network, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}
	visible, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}
	return &documentCookies{network: network, visible: visible}, nil
}

func (jar *documentCookies) Cookies(u *url.URL) []*http.Cookie {
	return jar.network.Cookies(u)
}

func (jar *documentCookies) SetCookies(u *url.URL, values []*http.Cookie) {
	jar.network.SetCookies(u, values)
	projected := make([]*http.Cookie, 0, len(values))
	for _, cookie := range values {
		if cookie.HttpOnly {
			expired := *cookie
			expired.MaxAge = -1
			projected = append(projected, &expired)
		} else {
			projected = append(projected, cookie)
		}
	}
	jar.visible.SetCookies(u, projected)
}
