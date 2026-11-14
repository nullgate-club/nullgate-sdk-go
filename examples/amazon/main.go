// Amazon submits an observed sign-in form with generated metadata1.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andybalholm/cascadia"
	"github.com/nullgate-club/nullgate-sdk-go/v2"
	"github.com/nullgate-club/nullgate-sdk-go/v2/amazon"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/browser"
	"golang.org/x/net/html"
)

func attr(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func run() error {
	address, ua, email := os.Getenv("TARGET_URL"), os.Getenv("TARGET_USER_AGENT"), os.Getenv("AMAZON_EMAIL")
	if address == "" || ua == "" || email == "" {
		return fmt.Errorf("set TARGET_URL, TARGET_USER_AGENT and AMAZON_EMAIL")
	}
	selector := os.Getenv("AMAZON_FORM_SELECTOR")
	if selector == "" {
		selector = "#signIn"
	}
	matcher, err := cascadia.Compile(selector)
	if err != nil {
		return fmt.Errorf("form selector: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Jar: jar}
	client, err := nullgate.New("", api.Options{})
	if err != nil {
		return err
	}
	defer client.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", ua)
	start := time.Now().UnixMilli()
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	end := time.Now().UnixMilli()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET target: %s", resp.Status)
	}
	pageURL := resp.Request.URL
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	forms := cascadia.QueryAll(doc, matcher)
	if len(forms) != 1 || forms[0].Data != "form" {
		return fmt.Errorf("form selector must match exactly one form")
	}
	form := forms[0]
	if !strings.EqualFold(attr(form, "method"), "post") {
		return fmt.Errorf("target form must use POST")
	}
	action, err := pageURL.Parse(attr(form, "action"))
	if err != nil {
		return err
	}
	values := url.Values{}
	for _, input := range cascadia.QueryAll(form, cascadia.MustCompile("input")) {
		if strings.EqualFold(attr(input, "type"), "hidden") && attr(input, "name") != "" {
			values.Add(attr(input, "name"), attr(input, "value"))
		}
	}
	values.Set("ap_email", email)
	session, err := browser.New(browser.Options{UserAgent: ua})
	if err != nil {
		return err
	}
	page, err := session.Page(pageURL.String(), string(body), browser.PageOptions{StartedAtMS: &start})
	if err != nil {
		return err
	}
	inputs, err := amazon.PrepareInputs(page, []browser.Input{{"name": "ap_email", "value": email}})
	if err != nil {
		return err
	}
	cookies := make(map[string]string)
	for _, cookie := range jar.Cookies(pageURL) {
		cookies[cookie.Name] = cookie.Value
	}
	product, err := client.Amazon.Session(session)
	if err != nil {
		return err
	}
	result, err := product.Fwcim(ctx, page, amazon.FwcimOptions{Form: selector, Timing: map[string]float64{"navigationStart": float64(start), "fetchStart": float64(start), "responseEnd": float64(end)}, Inputs: inputs, Cookies: cookies})
	if err != nil {
		return err
	}
	values.Set("metadata1", result.Metadata1)
	if err := result.Wait(ctx); err != nil {
		return err
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	for name, value := range result.Headers {
		post.Header.Set(name, value)
	}
	post.Header.Set("User-Agent", ua)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(post)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("POST target: %s", response.Status)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	fmt.Printf("Form submitted: %s\n", response.Status)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
