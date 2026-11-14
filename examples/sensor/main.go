// Sensor sends generated requests with the same caller-owned cookie jar.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2"
)

func fetch(ctx context.Context, client *http.Client, address, ua string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("GET target: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), resp.Request.URL.String(), err
}

func send(ctx context.Context, client *http.Client, generated *nullgate.Request) error {
	if err := generated.Wait(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, generated.URL, bytes.NewReader(generated.Body))
	if err != nil {
		return err
	}
	for name, value := range generated.Headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST target: %s", resp.Status)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func run() error {
	address, ua := os.Getenv("TARGET_URL"), os.Getenv("TARGET_USER_AGENT")
	if address == "" || ua == "" {
		return fmt.Errorf("set TARGET_URL and TARGET_USER_AGENT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Jar: jar}
	client, err := nullgate.NewClient("", nullgate.Options{})
	if err != nil {
		return err
	}
	defer client.Close()
	html, pageURL, err := fetch(ctx, httpClient, address, ua)
	if err != nil {
		return err
	}
	session, err := client.Session(nullgate.SessionOptions{UserAgent: ua})
	if err != nil {
		return err
	}
	page, err := session.Page(pageURL, html, nullgate.PageOptions{})
	if err != nil {
		return err
	}
	scriptURL := os.Getenv("TARGET_SCRIPT_URL")
	if scriptURL == "" {
		scriptURL, err = page.SensorURL()
		if err != nil {
			return err
		}
		if scriptURL == "" {
			return fmt.Errorf("sensor script not found; set TARGET_SCRIPT_URL")
		}
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return err
	}
	ref, err := url.Parse(scriptURL)
	if err != nil {
		return err
	}
	scriptURL = base.ResolveReference(ref).String()
	script, _, err := fetch(ctx, httpClient, scriptURL, ua)
	if err != nil {
		return err
	}
	pixelURL, err := page.PixelURL()
	if err != nil {
		return err
	}
	for i := range 4 {
		u, err := url.Parse(scriptURL)
		if err != nil {
			return err
		}
		cookies := make(map[string]string)
		for _, cookie := range jar.Cookies(u) {
			cookies[cookie.Name] = cookie.Value
		}
		request, err := page.Sensor(ctx, nullgate.SensorOptions{Script: script, ScriptURL: scriptURL, Cookies: cookies})
		if err != nil {
			return err
		}
		if err := send(ctx, httpClient, request); err != nil {
			return err
		}
		fmt.Printf("Sensor %d sent\n", i+1)
		if i == 0 && pixelURL != "" {
			pixelScript, _, err := fetch(ctx, httpClient, pixelURL, ua)
			if err != nil {
				return err
			}
			pixel, err := page.Pixel(ctx, nullgate.PixelOptions{Script: pixelScript, ScriptURL: pixelURL})
			if err != nil {
				return err
			}
			if err := send(ctx, httpClient, pixel); err != nil {
				return err
			}
			fmt.Println("Pixel sent")
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
