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
| Akamai | `Page.Sensor`, `Page.Pixel`, `Page.Sbsd` | [Akamai](https://nullgate.club/en/akamai) |
| Amazon FWCIM | `Page.Fwcim` returns `metadata1` for the original form | [Amazon](https://nullgate.club/en/amazon) |
| Amazon ACIC | `Client.AcicPow`, `Client.AcicWaf` | [ACIC](https://nullgate.club/en/amazon-acic) |
| ThreatMetrix | `Page.ThreatMetrix` starts a profiling session | [ThreatMetrix](https://nullgate.club/en/threatmetrix) |
| Classifier | `Client.Classify` chooses a label, `Client.Match` scores independent queries | [Classifier](https://nullgate.club/en/classifier) |

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
)

func main() {
    client, err := nullgate.NewClient("", nullgate.Options{})
    if err != nil { log.Fatal(err) }
    defer client.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    account, err := client.Account(ctx)
    if err != nil { log.Fatal(err) }
    fmt.Printf("Balance: %s %s\n", account.Balance, account.Currency)
}
```

An empty key makes `NewClient` read `NULLGATE_API_KEY`. Pass a context to every SDK network operation and wait. Close the client when finished. `Client.Usage(ctx, nullgate.UsageOptions{})` retrieves usage buckets. Monetary values are decimal strings, not floating-point amounts. See [billing and prices](https://nullgate.club/en/billing).

## Examples

Run these commands from the SDK checkout. Use an authorized target and your actual user agent.

### Akamai sensor and pixel

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

[ACIC](examples/acic/main.go) and [ThreatMetrix](examples/threatmetrix/main.go) examples show their complete caller-owned transport flows.

## Sessions and inputs

Create a session with `client.Session(nullgate.SessionOptions{UserAgent: ua})`, then create a page with `session.Page(url, html, nullgate.PageOptions{})`. Reuse the session for the same browser identity and product continuation. Create a new page for each navigation. Product states remain separate within a session. `Page.SensorURL`, `Page.PixelURL`, and `Page.SbsdURL` discover script URLs from that page. An empty result means none was found, and ambiguous discovery returns an error. Supply an explicit script URL when needed.

`Page.Inputs` matches ordinary raw values by control ID or name and summarizes them locally. It rejects passwords. For passwords, use `nullgate.PrepareInputs` explicitly with an input's ID or name and value. It returns `PreparedInput` values without retaining the raw value. Do not put passwords in logs, attributes, selectors, or FWCIM extras. Optional input and action slices distinguish `nil` (omitted) from an empty slice (explicitly empty).

For FWCIM, use `Page.FwcimInputs([]nullgate.Input{...})` before discarding the raw values. It computes source-compatible CRC32 checksums and includes email text for the canvas probe. It never includes password text or password checksums. Precomputed nonempty submitted nonpassword observations require `Checksum`, and the selected email also requires `Text`. Supply observed `Timing` with `navigationStart` in Unix milliseconds. If `PageOptions.StartedAtMS` is set, it must match. Supply `PreparedInput.Geometry` only when measured. Wait on the result before submitting `Metadata1` with the original form and its target cookies.

For ACIC, `DiscoverAcic`, `ParseAcicResult`, `DiscoverAcicWaf`, and their setup methods prepare the challenge and continuation requests. Send these with your target client. `AcicPowResult.Wait` enforces its send time. `AcicWafResult.VerificationBody` builds the WAF verification body. The SDK does not retry ACIC generation, because a request can be billed even if its response is lost.

For ThreatMetrix, provide the target fetch callback and keep the startup context alive for the profile lifetime. `WaitCollected` waits for collection, `Pagehide` signals departure, and `Close` stops the profile. Ready startup alone does not mean collection or target acceptance.

## Transport and reporting

`Options.HTTPClient` configures only calls to the Nullgate API. It does not send target requests. The SDK copies the client and disables its cookies and redirects. Keep target cookies and proxy settings in your own client. `net/http` does not preserve wire header order. Use a suitable caller-owned transport if your target requires it.

The SDK gzips JSON API requests of at least 1024 bytes. It can fall back to plain JSON when supported by the operation. Sensor script retention sends the script once when the server retains it, then falls back to the full script when needed. Context cancellation stops SDK waits and API operations. Your target transport and ThreatMetrix callback must honor their own contexts.

`Client.Report` and result `Report` methods submit anonymous request analytics. A `true` result means HTTP delivery only, not target acceptance or a refund.

## Errors

Use `errors.As(err, &apiError)` with a `var apiError *nullgate.Error` to inspect `Code`, `Message`, `Status`, and `RequestID`. Default error formatting omits the message and underlying transport error to avoid printing request contents. `errors.Is(err, context.Canceled)` and `errors.Is(err, context.DeadlineExceeded)` retain their usual meaning.

## Repository layout

The root package exposes the client, sessions, page operations, and result types. Private API transport, document parsing, ACIC parsing, profiling protocol, and TURN handling live in `internal/`. Runnable programs live in `examples/`. There is no application server or generated `pkg/` facade.

## Migration and development

Version 2 is a clean replacement for the v1 branch, not a drop-in upgrade. Change imports to `github.com/nullgate-club/nullgate-sdk-go/v2` and migrate callers to the v2 API.

CI runs `make setup` followed by `make check` with Go 1.24.1 or newer. See [sessions](https://nullgate.club/en/sessions) and [errors](https://nullgate.club/en/errors) for more details.
