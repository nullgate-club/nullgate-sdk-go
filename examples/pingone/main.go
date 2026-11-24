// Command pingone generates Protect data using a caller-owned HTTP client.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"github.com/nullgate-club/nullgate-sdk-go/v2/pingone"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	url, scriptURL := os.Getenv("TARGET_URL"), os.Getenv("PINGONE_SCRIPT_URL")
	if url == "" || scriptURL == "" {
		return fmt.Errorf("TARGET_URL and PINGONE_SCRIPT_URL are required")
	}
	userAgent := os.Getenv("USER_AGENT")
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	target := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	fetch := func(url string) (string, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", "", err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := target.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", "", fmt.Errorf("target returned status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		return string(body), resp.Request.URL.String(), err
	}
	html, pageURL, err := fetch(url)
	if err != nil {
		return err
	}
	script, _, err := fetch(scriptURL)
	if err != nil {
		return err
	}
	client, err := nullgate.New("", api.Options{})
	if err != nil {
		return err
	}
	defer client.Close()
	visit, err := browser.New(browser.Options{UserAgent: userAgent})
	if err != nil {
		return err
	}
	page, err := visit.Page(pageURL, html, browser.PageOptions{})
	if err != nil {
		return err
	}
	session, err := client.PingOne.Session(visit)
	if err != nil {
		return err
	}
	result, err := session.Protect(ctx, page, pingone.Options{Script: script, Send: target.Do})
	if err != nil {
		return err
	}
	fmt.Println(result.SDKVersion, result.DeviceID, result.RequestID)
	return nil
}
