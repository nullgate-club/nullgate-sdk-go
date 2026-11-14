<div align="center">

<img src="https://nullgate.club/assets/avatar.svg" alt="Nullgate" width="120">

# Nullgate Go SDK 2

**Prepare protection requests. Your HTTP client sends them.**

[![Go 1.24.1+](https://img.shields.io/badge/Go-1.24.1%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Docs](https://img.shields.io/badge/docs-nullgate.club-56856a)](https://nullgate.club)
[![Telegram bot](https://img.shields.io/badge/Telegram-%40nullgate__app-26A5E4?logo=telegram&logoColor=white)](https://t.me/nullgate_app)

</div>

The SDK calls the Nullgate API and prepares requests for target sites. You own target HTTP, cookies, proxies, and submission.

| Product | Methods | Guide |
|---|---|---|
| Akamai | `akamai.Session.Sensor`, `Pixel`, `Sbsd` | [Akamai](https://nullgate.club/en/akamai) |
| Amazon FWCIM | `amazon.Session.Fwcim` returns `metadata1` for the original form | [Amazon](https://nullgate.club/en/amazon) |
| Amazon ACIC | `client.Amazon.ACIC.Pow`, `Waf` | [ACIC](https://nullgate.club/en/amazon-acic) |
| ThreatMetrix | `threatmetrix.Session.Start` starts a profiling session | [ThreatMetrix](https://nullgate.club/en/threatmetrix) |
| Classifier | `client.Classifier.Classify`, `Match` | [Classifier](https://nullgate.club/en/classifier) |

## Quick start

Get an API key from [@nullgate_app](https://t.me/nullgate_app). Install the SDK into your Go module:

```sh
go get github.com/nullgate-club/nullgate-sdk-go/v2@main
export NULLGATE_API_KEY='ng_your_key'
```

Save this as `main.go` and run `go run main.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/nullgate-club/nullgate-sdk-go/v2"
    "github.com/nullgate-club/nullgate-sdk-go/v2/api"
)

func main() {
    client, err := nullgate.New("", api.Options{})
    if err != nil { log.Fatal(err) }
    defer client.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    account, err := client.Accounts.Get(ctx)
    if err != nil { log.Fatal(err) }
    fmt.Printf("Balance: %s %s\n", account.Balance, account.Currency)
}
```

An empty key makes `nullgate.New` read `NULLGATE_API_KEY`. Pass a context to every SDK network operation and wait. Close the client when finished. `client.Accounts.Usage(ctx, accounts.UsageOptions{})` retrieves usage buckets from the `accounts` package. Monetary values are decimal strings, not floating-point amounts. See [billing and prices](https://nullgate.club/en/billing).

The root client assembles all products. For a single product, you can instead create a shared connection with `api.New` and pass it to `classifier.New`. Close the connection when finished.

## Examples

Run these commands from the SDK checkout. Use an authorized target and your actual user agent.

### Akamai sensor and pixel
This complete example reads previously fetched page and sensor script files, then sends one sensor request. Set `TARGET_URL`, `TARGET_SCRIPT_URL`, and `TARGET_USER_AGENT` to the observed values. In a real visit, fetch both files and send the request with the same target client and cookie jar. Include current cookies in `akamai.SensorOptions.Cookies`.

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "io"
    "net/http"
    "os"

    "github.com/nullgate-club/nullgate-sdk-go/v2"
    "github.com/nullgate-club/nullgate-sdk-go/v2/akamai"
    "github.com/nullgate-club/nullgate-sdk-go/v2/api"
    "github.com/nullgate-club/nullgate-sdk-go/v2/browser"
)

func run() error {
    html, err := os.ReadFile("page.html")
    if err != nil { return err }
    script, err := os.ReadFile("sensor.js")
    if err != nil { return err }
    client, err := nullgate.New("", api.Options{})
    if err != nil { return err }
    defer client.Close()
    visit, err := browser.New(browser.Options{UserAgent: os.Getenv("TARGET_USER_AGENT")})
    if err != nil { return err }
    page, err := visit.Page(os.Getenv("TARGET_URL"), string(html), browser.PageOptions{})
    if err != nil { return err }
    session, err := client.Akamai.Session(visit)
    if err != nil { return err }
    ctx := context.Background()
    sensor, err := session.Sensor(ctx, page, akamai.SensorOptions{
        Script: string(script), ScriptURL: os.Getenv("TARGET_SCRIPT_URL"),
    })
    if err != nil { return err }
    if err := sensor.Wait(ctx); err != nil { return err }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, sensor.URL, bytes.NewReader(sensor.Body))
    if err != nil { return err }
    for name, value := range sensor.Headers { req.Header.Set(name, value) }
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 { return fmt.Errorf("target: %s", resp.Status) }
    _, err = io.Copy(io.Discard, resp.Body)
    return err
}

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
```

For a complete visit with discovery and a cookie jar, run the example below.


```sh
export NULLGATE_API_KEY='ng_your_key'
export TARGET_URL='https://your-target.example/'
export TARGET_USER_AGENT='your actual browser user agent'
go run ./examples/sensor
```

The [sensor example](examples/sensor/main.go) fetches the page and script with one cookie jar, then sends up to four sensors. When a pixel is discovered, it sends it after the first sensor. If sensor discovery is ambiguous or empty, set `TARGET_SCRIPT_URL` to the observed script URL. The example reports HTTP status, not target acceptance. Go's `net/http` is not Chrome's TLS fingerprint and cannot guarantee acceptance.

### Amazon FWCIM

```sh
export NULLGATE_API_KEY='ng_your_key'
export TARGET_URL='https://www.amazon.com/ap/signin'
export TARGET_USER_AGENT='your actual browser user agent'
export AMAZON_EMAIL='your-email'
go run ./examples/amazon
```

The [Amazon example](examples/amazon/main.go) fetches the form, keeps its hidden fields, and submits `metadata1` with `ap_email`. Set `AMAZON_FORM_SELECTOR` if the form is not `#signIn`. It records request start and response end as observed timing, not browser performance measurements. It does not invent geometry. The server can apply its recognized Amazon `a-input-text` default where applicable. Adapt the form fields to the observed target flow before submitting.

### Classifier

```sh
export NULLGATE_API_KEY='ng_your_key'
go run ./examples/classifier classify photo.jpg 'a cat' 'a dog'
go run ./examples/classifier match photo.jpg 'a cat' 'a dog'
```

The [classifier example](examples/classifier/main.go) accepts raw JPEG, PNG, or WebP files. Classify prints the best label. Match prints independent scores, which do not have to sum to one.

Call `client.Classifier.Classify(ctx, classifier.ClassifyOptions{...})` with images and labels, or `client.Classifier.Match(ctx, classifier.MatchOptions{...})` with images and queries.

[ACIC](examples/acic/main.go) and [ThreatMetrix](examples/threatmetrix/main.go) examples show their complete caller-owned transport flows.

## Sessions and inputs

Create an immutable browser identity with `browser.New(browser.Options{UserAgent: ua})`. Create each navigation with `visit.Page(url, html, browser.PageOptions{})`. Create a product session with `client.Akamai.Session(visit)` and reuse both the visit and that product session within the visit. A product session rejects a page from another visit. Other products have separate continuation state.

`akamai.SensorURL(page)`, `akamai.PixelURL(page)`, and `akamai.SbsdURL(page)` discover script URLs. An empty result means none was found, and ambiguous discovery returns an error. Supply an explicit script URL when needed. Use `session.Sensor(ctx, page, akamai.SensorOptions{...})`, `session.Pixel(ctx, page, akamai.PixelOptions{...})`, or `session.Sbsd(ctx, page, akamai.SbsdOptions{...})`.

`page.Inputs` matches ordinary raw values by control ID or name and summarizes them locally. It rejects passwords. For passwords, use `browser.PrepareInputs([]browser.Input{...})` explicitly with an input's ID or name and value. It returns `browser.PreparedInput` values without retaining the raw value. Do not put passwords in logs, attributes, selectors, or FWCIM extras. Optional input and action slices distinguish `nil` (omitted) from an empty slice (explicitly empty).

For FWCIM, create and reuse `client.Amazon.Session(visit)` and call `session.Fwcim(ctx, page, amazon.FwcimOptions{...})`. Use `amazon.PrepareInputs(page, []browser.Input{...})` before discarding raw values. It returns `amazon.Input` values, which embed browser summaries and add FWCIM-only metadata. It computes source-compatible CRC32 checksums and includes email text for the canvas probe. It never includes password text or password checksums. Precomputed nonempty submitted nonpassword observations require `Checksum`, and the selected email also requires `Text`. Supply observed `Timing` with `navigationStart` in Unix milliseconds. If `browser.PageOptions.StartedAtMS` is set, it must match. Supply `amazon.Input.Geometry` only when measured. Wait on the result before submitting `Metadata1` with the original form and its target cookies.

For ACIC, use `acic.Discover`, `acic.ParseResult`, and `acic.DiscoverWaf` from `amazon/acic` and their setup methods. Call `client.Amazon.ACIC.Pow` and `client.Amazon.ACIC.Waf` and send the prepared requests with your target client. `PowResult.Wait` enforces its send time. `WafResult.VerificationBody` builds the WAF verification body. The SDK does not retry ACIC generation, because a request can be billed even if its response is lost.

For ThreatMetrix, create and reuse `client.ThreatMetrix.Session(visit)`, then call `session.Start(ctx, page, threatmetrix.Options{...})`. Provide the target fetch callback and keep the startup context alive for the profile lifetime. `WaitCollected` waits for collection, `Pagehide` signals departure, and `Close` stops the profile. Ready startup alone does not mean collection or target acceptance.

## Transport and reporting

`api.Options.HTTPClient` configures only calls to the Nullgate API. It does not send target requests. The SDK copies the client and disables its cookies and redirects. Keep target cookies and proxy settings in your own client. `net/http` does not preserve wire header order. Use a suitable caller-owned transport if your target requires it.

The SDK gzips JSON API requests of at least 1024 bytes. It can fall back to plain JSON when supported by the operation. Sensor script retention sends the script once when the server retains it, then falls back to the full script when needed. Context cancellation stops SDK waits and API operations. Your target transport and ThreatMetrix callback must honor their own contexts.

`Client.Report` and result `Report` methods submit anonymous request analytics. A `true` result means HTTP delivery only, not target acceptance or a refund.

## Errors

Use `errors.As(err, &apiError)` with `var apiError *api.Error` to inspect `Code`, `Message`, `Status`, and `RequestID`. Error formatting includes `Message`, but not the underlying `Cause` or credentials. Use `errors.Is(err, api.ErrClosed)` for a closed client. `errors.Is(err, context.Canceled)` and `errors.Is(err, context.DeadlineExceeded)` retain their usual meaning.

## Repository layout

The root package assembles the client. Public packages own their models and operations:

```text
api/              Shared API connection, options, and errors
accounts/         Account and usage
browser/          Browser identity, pages, and input summaries
akamai/           Akamai sessions and requests
amazon/           FWCIM sessions and input metadata
amazon/acic/      ACIC discovery and PoW/WAF
threatmetrix/     ThreatMetrix sessions and profiles
classifier/       Image classification and matching
internal/         Private protocol, parsing, and transport support
examples/         Runnable caller-owned target flows
```

## Migration and development

Version 2 is a clean replacement for the SDK in the `v1` branch, not a drop-in upgrade. Change imports to `github.com/nullgate-club/nullgate-sdk-go/v2` and migrate callers to the v2 API. The root package has no session, options, error, or model aliases.

If you used the initial flat v2 API, replace `nullgate.NewClient` with `nullgate.New` and use `api.Options` and `api.Error`. Replace `client.Session` and page-level product methods with a browser visit and product sessions, as shown above. The flat API has no compatibility aliases.

CI runs `make setup` followed by `make check` with Go 1.24.1 or newer. See [sessions](https://nullgate.club/en/sessions) and [errors](https://nullgate.club/en/errors) for more details.
