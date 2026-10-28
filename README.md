# Nullgate Go SDK

Typed clients for Nullgate's Akamai Pixel, Sensor and SBSD APIs, local protection
discovery, isolated document sessions and ready-to-send solutions. The SDK's
`net/http` client talks to Nullgate, not to your target website.

This SDK requires the updated backend with `X-Request-ID` and analytics reporting.
Until the backend cutover, set `Options.BaseURL` and `Options.AnalyticsURL` to an
updated preview deployment. It is not compatible with the old production API;
Python users of that API should stay on the Python SDK's `main` branch.

## Install from GitHub

Go 1.24.1 or newer:

```sh
go get github.com/nullgate-club/nullgate-sdk-go@main
```

The module is source-installed from public GitHub; there is no separate package
registry release. Git must be available for direct source downloads.

## Client and document lifetime

Create one reusable client with `nullgate.NewClient(apiKey, nullgate.Options{
BaseURL: previewURL, AnalyticsURL: analyticsURL})`, check its error, and
`defer client.Close()` at application shutdown. Create a new session for each new
document; reuse the identity UUID and your target provider's cookie jar across
navigation, not session state.

```go
package example

import (
	"context"

	nullgate "github.com/nullgate-club/nullgate-sdk-go"
)

func generateSensor(
	ctx context.Context,
	client *nullgate.Client,
	identity, userAgent string,
	sensor nullgate.Sensor,
	script string,
	cookies map[string]string,
) (*nullgate.Solution, error) {
	session, err := client.Open(nullgate.SessionOptions{
		Identity: identity, UserAgent: userAgent,
	})
	if err != nil {
		return nil, err
	}
	defer session.Close()

	return session.Solve(ctx, nullgate.SensorParams{
		Protection: sensor, Script: script, Cookies: cookies,
	})
}
```

`nullgate.FindProtections(nullgate.Page{URL: pageURL, HTML: html})` performs local
synchronous discovery and returns candidates plus an error. Select the intended
concrete `nullgate.Sensor`, `nullgate.Pixel` or `nullgate.Sbsd` explicitly when
ambiguous; fetch its `ScriptURL` with your target client. Discovery does not fetch
scripts or execute JavaScript, and a candidate is not proof of a supported source.

Use `PixelParams{Protection: pixel, Script: script}` or
`SbsdParams{Protection: sbsd, Script: script, Cookies: cookies}` for the other
protection kinds. Sensor inputs/actions are optional; nil preserves server
defaults while non-nil empty slices explicitly send empty lists. Raw input values
are summarized and hashed locally before transmission.

## Send and report

After `solution.Wait(ctx)`, send `solution.Method`, `solution.URL`,
`solution.Headers` and the exact string `solution.Body` through your target
provider. Do not JSON-encode the body again. `SendAt` is an absolute Unix timestamp
in seconds; `RequestID` comes from the response's actual `X-Request-ID` header.
Your target provider owns redirects, proxy settings and cookie scope. Never send
the Nullgate API key to the target website.

After an observed target failure, `solution.Report(ctx)` or
`client.Report(ctx, solution.RequestID)` sends only the request ID to analytics.
A true result means HTTP delivery, not report acceptance, clearance or a refund.
Reporting does not send account authorization, state headers or target cookies.
Contexts control cancellation and deadlines; close the client only after its
sessions and reports are finished.

## Runnable target example

[examples/target/main.go](examples/target/main.go) uses `tls-client` with its
Chrome 146 profile, a matching Windows User-Agent, persistent connections and a
scope-aware cookie jar. It fetches page/script content, solves, waits and posts
the exact body; it has no standard-transport fallback.

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-go.git
cd nullgate-sdk-go
export TARGET_URL='https://your-target.example/page'
export NULLGATE_API_KEY='your-account-key'
go run ./examples/target
```

Optional environment variables are `NULLGATE_IDENTITY`, `TARGET_PROXY`,
`NULLGATE_BASE_URL` and `ANALYTICS_URL`; configure the last two for the updated
preview deployment before backend cutover. A closed sensor cookie gate is not
proof of target acceptance. Blocking SBSD is checked by re-fetching the original
page, not by treating POST 200 as clearance. Verify your intended target content.

## Develop

```sh
make setup
make format
make check
```

Standalone CI runs `make setup` and `make check`, using the Go version in
`go.mod`. The gate checks `gofmt`, runs `go vet ./...`, and runs the behavioral
suite with `go test -race ./...`, including compilation of the target example.
Canonical SDK-first documentation: [docs.nullgate.club](https://docs.nullgate.club).
