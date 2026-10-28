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

With a discovered `sensor`, its fetched `script` and the target's current
`cookies`, a single generation is shown below. `target` is your `tls-client`
client and `http` is `github.com/bogdanfinn/fhttp`.

```go
session, err := client.Open(nullgate.SessionOptions{
	Identity: identity, UserAgent: userAgent,
})
if err != nil {
	return err
}
defer session.Close()

solution, err := session.Solve(ctx, nullgate.SensorParams{
	Protection: sensor, Script: script, Cookies: cookies,
})
if err != nil {
	return err
}
if err := solution.Wait(ctx); err != nil {
	return err
}
post, err := http.NewRequestWithContext(
	ctx, solution.Method, solution.URL, strings.NewReader(solution.Body),
)
if err != nil {
	return err
}
for name, value := range solution.Headers {
	post.Header.Set(name, value)
}
target.SetFollowRedirect(false)
response, err := target.Do(post)
if err != nil {
	return err
}
defer response.Body.Close()
fmt.Println(response.StatusCode)
```

`nullgate.FindProtections(page)` and `client.FindProtections(page)` perform local,
synchronous discovery. Zero matches return an empty list; one returns a
single-element list. Multiple matches return `*nullgate.AmbiguousProtectionError`
with a `Count` field. These functions return normal errors; they never invoke Go
`panic`.

Call `nullgate.FindProtections(page, false)` (or the client method with `false`)
to inspect every original candidate and its provenance, then select the intended
concrete `nullgate.Sensor`, `nullgate.Pixel` or `nullgate.Sbsd` yourself. No
candidate is silently selected or deduplicated. Fetch its `ScriptURL` with your
target client. Discovery does not fetch scripts or execute JavaScript, and a
candidate is not proof of a supported source.

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

[examples/target/main.go](examples/target/main.go) is a sequential, one-generation
program using `tls-client`'s Chrome 146 profile, a matching Windows User-Agent and
its native cookie jar and `GetCookies` API. It performs one page GET, local
discovery, one script GET, one solve, the scheduled wait and one exact POST, then
prints the target response. It has no transport fallback, automatic generation
loop or custom cookie adapter.

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-go.git
cd nullgate-sdk-go
export TARGET_URL='https://your-target.example/page'
export NULLGATE_API_KEY='your-account-key'
go run ./examples/target
```

`NULLGATE_IDENTITY` optionally supplies a stable identity UUID; otherwise the
example generates one. `NULLGATE_BASE_URL` and `ANALYTICS_URL` select the updated
preview services before backend cutover.

One POST demonstrates one generation, not target clearance. If your target needs
another generation on the same document, reuse the session and refresh cookies
from the target client before solving again. After navigation, open a new
session; keep the identity and target cookie jar. For blocking SBSD, revisit the
original page and check the intended content rather than treating POST 200 as
clearance.

## Develop

```sh
make setup
make format
make check
```

Standalone CI runs `make setup` and `make check`, using the Go version in
`go.mod`. The gate checks `gofmt`, runs `go vet ./...`, and runs the behavioral
suite with `go test -race ./...`, including compilation of the target example.
Canonical SDK-first documentation: [Quickstart](https://docs.nullgate.club/en/quickstart).
