# Nullgate Go SDK

Typed clients for Nullgate's Akamai Pixel, Sensor and SBSD APIs and active
ThreatMetrix profiling, with local protection discovery and isolated documents.
The SDK's `net/http` client talks to Nullgate, not to your target website.

Default endpoints are `https://akamai.nullgate.club` for generation,
`https://threatmetrix.nullgate.club` for profiling and
`https://analytics.nullgate.club` for optional diagnostic reports. `Options`
exposes `BaseURL`, `ProfileBaseURL` and `AnalyticsURL` overrides.

## Install from GitHub

Go 1.24.1 or newer:

```sh
go get github.com/nullgate-club/nullgate-sdk-go@main
```

The module is source-installed from public GitHub; there is no separate package
registry release. Git must be available for direct source downloads.

## Client and document lifetime

Create one reusable client with `nullgate.NewClient(apiKey, nullgate.Options{})`,
check its error, and `defer client.Close()` at application shutdown.
For Akamai, create a new session for each new document; reuse the identity UUID
and your target provider's cookie jar across navigation. For ThreatMetrix, a
session may begin profiles for subsequent documents to retain server-side
provider storage. Each active profile owns exactly one document and socket.

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
concrete `nullgate.Sensor`, `nullgate.Pixel`, `nullgate.Sbsd` or
`nullgate.ThreatMetrix` yourself. No candidate is silently selected or
deduplicated. Fetch `ScriptURL` for Akamai; ThreatMetrix uses its actual `TagsURL`
through `Profile`. Discovery does not fetch scripts or execute JavaScript, and a
candidate is not proof of a supported source. ThreatMetrix detection permits
cross-origin `/tags.js` URLs with exactly one nonempty `org_id` and `session_id`,
without a site allowlist. Mixed providers follow the same ambiguity policy.

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

## Active ThreatMetrix profiling

`Session.Profile` is separate from `Solve` and returns an active `*Profile`, not a
POST instruction. Supply the detected nominal protection and a reusable target:

```go
// fetch is your context-aware, concurrency-safe target HTTP adapter:
// func(context.Context, nullgate.TargetRequest) (nullgate.TargetResponse, error)
// proxyURL is the SAME route used by fetch. "" explicitly means direct.
target, err := nullgate.NewTarget(fetch, proxyURL)
if err != nil {
	return err // Invalid proxy configuration fails before starting a paid profile.
}
profile, err := session.Profile(ctx,
	nullgate.ThreatMetrixParams{Protection: protection}, target)
if err != nil {
	return err
}
defer profile.Close()
fmt.Println(profile.RequestID) // Source request ID; startup delivered, not acceptance.

// Keep ctx and profile alive while this document is active.
// When the caller actually leaves the page:
if err := profile.Pagehide(ctx, nil, false); err != nil {
	return err
}
if err := profile.WaitCollected(ctx); err != nil {
	return err
}
```

For a caller-generated direct collector URL, use the validated constructor
instead of discovery. It returns the same `ThreatMetrix` type accepted by
`ThreatMetrixParams`:

```go
// Use the real site's document and explicit IDs from your application flow.
protection, err := nullgate.NewThreatMetrixCollector(
	nullgate.Page{URL: pageURL, HTML: pageHTML},
	collectorURL, orgID, sessionID,
)
if err != nil {
	return err
}
profile, err := session.Profile(ctx,
	nullgate.ThreatMetrixParams{Protection: protection}, target)
if err != nil {
	return err
}
defer profile.Close()
```

The collector URL must be absolute HTTP(S), with a host and valid port, without
userinfo, fragments, raw whitespace or backslashes. Its path and query are kept
unchanged. Supply non-whitespace `orgID` and `sessionID` strings without line
breaks; the SDK does not recover IDs from URL parameters, wrappers or source maps.
Use exactly the same `sessionID` in the site's matching hidden form input. It is
not the Nullgate continuation state ID, and profiling is not an acceptance guarantee.
Keep `Page` as the real site's document, not the collector URL or `about:blank`.

Direct collector and tags entries are mutually exclusive. Do not set `TagsURL`
on a value returned by `NewThreatMetrixCollector`; missing or mixed entry sources
fail before connecting or invoking the target callback. Discovered and manually
supplied tags entries remain supported with their existing behavior.

`ThreatMetrixParams` also accepts the existing `Inputs []Input` and
`Actions []Action` observations. Inputs use the same local value hashing as
`SensorParams`; input/change action values must be prepared `InputValue` summaries;
raw string values are rejected before connecting. Nil collections are omitted;
explicit empty slices are sent as `[]` to clear observations. Only supplied
observations are included: profiling does not record or invent keystrokes.

`TargetRequest` carries `Role`, `URL`, `Method`, `Headers`, raw `Body []byte` and
the explicit native `CredentialsInclude`/`CredentialsOmit` mode. Nil body means
absent; a non-nil empty slice means present-empty. Return actual
`TargetResponse{Status, Headers, Body}` bytes, including HTTP error statuses.
Connection failures are errors, not invented HTTP successes. The SDK performs
the strict base64 wire conversion and timestamps response completion itself.

Direct entry fetches arrive with `Role: "collector"` through that same callback.
Every successfully issued target HTTP command is billed, including resource loads
and target report requests. HTTP result callbacks, WebSocket lifecycle controls
and ICE/TURN are not billed separately.

The callback retains your existing TLS provider, cookie jar and HTTP proxy.
For `omit`, use the provider's per-request no-cookie facility: neither send nor
retain cookies, including on redirects. Never clear or replace the shared jar.
[examples/profile/main.go](examples/profile/main.go) shows this with the standard
`net/http` provider: a per-request client copy with `Jar=nil`, leaving the shared
jar intact. A `fhttp`/`tls-client` adapter can use the same nominal DTOs; it must
provide equivalent native cookie isolation and honor cancellation.

`NewTarget(fetch, proxyURL)` supports SOCKS5/SOCKS5h and HTTP(S) CONNECT.
The proxy URL and its credentials stay local; they never go to the API or
default debug output. TURN uses that explicit route over TCP, with a UDP relay
allocation but no local UDP socket, host gathering or direct fallback. It holds
the actual allocation until `ice.release` or close, then requests release and
closes the stream without waiting for a TURN release acknowledgment.
The API WebSocket is separate and never adopts environment proxy settings.

`Profile` returns at `ready`. `WaitCollected(ctx)` waits for the later
`collected` fact; neither implies target acceptance or closes the socket.
`Pagehide(ctx, atMS, persisted)` waits for the departure acknowledgment while
background HTTP/ICE continues. Nil `atMS` samples caller wall time; an explicit
`*int64` supplies Unix milliseconds. Persisted departure does not close the
profile. Canceling a sent Pagehide closes the profile because acknowledgments
have no correlation ID.

`Close`, session close, client close, or cancellation of the context originally
passed to `Profile` release network work without inventing pagehide.
Explicit `Close` sends a normal WebSocket close frame before closing the connection.
`Done()` closes after cleanup; `Err()` exposes typed `APIError`, `ProtocolError`
or `TransportError` (including source `RequestID`) or cancellation.
Target callbacks must stop on their context so cleanup can join them.
After an observed target failure, `profile.Report(ctx)` uses the same anonymous
analytics semantics as `solution.Report`.

Run the profiling example with `TARGET_URL`, `NULLGATE_API_KEY`, optional
`NULLGATE_IDENTITY`, and explicit `TARGET_PROXY` (empty means direct).
`NULLGATE_PROFILE_BASE_URL` overrides the API for local verification:

```sh
go run ./examples/profile
```

To select explicit collector mode, also supply all three values below. This
skips tags discovery; incomplete or malformed collector inputs fail before the
example fetches the target page:

```sh
TMX_COLLECTOR_URL='https://your-collector.example/caller-generated-path?opaque=value' \
TMX_ORG_ID='site-org-id' TMX_SESSION_ID='site-session-id' \
go run ./examples/profile
```

It deliberately departs immediately after startup; real applications keep the
profile active for the document's actual lifetime. This standard HTTP example
does not emulate browser TLS or claim target clearance.

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
example generates one. `NULLGATE_BASE_URL` and `ANALYTICS_URL` override the default
services for local development or staging.

One POST demonstrates one generation, not target clearance. If your target needs
another generation on the same document, reuse the session and refresh cookies
from the target client before solving again. After navigation, open a new
session; keep the identity and target cookie jar. For blocking SBSD, revisit the
original page and check the intended content rather than treating POST 200 as
clearance.

## Develop

The module root is the public `nullgate` library; its import path stays
`github.com/nullgate-club/nullgate-sdk-go`.

- `internal/profilewire` owns private connection messages and strict JSON decoding.
- `internal/turn` owns TCP proxy routing and the Pion allocation lifecycle.
- `examples/` contains runnable consumers of the public API.

Public client, session, profile and target types stay together. Internal packages
do not import the public package or expose compatibility aliases.

```sh
make setup
make format
make check
```

Standalone CI runs `make setup` and `make check`, using the Go version in
`go.mod`. The gate checks `gofmt`, runs `go vet ./...`, and runs the behavioral
suite with `go test -race ./...`, including compilation of the target example.
Canonical SDK-first documentation: [Quickstart](https://docs.nullgate.club/en/quickstart).
