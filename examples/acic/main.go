// Command acic solves an ACIC page using caller-owned target HTTP clients.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	nullgate "github.com/nullgate-club/nullgate-sdk-go/v2"
)

func send(ctx context.Context, client *http.Client, req *nullgate.AcicRequest) (*http.Response, []byte, error) {
	r, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, nil, err
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0")
	transport := *client
	if req.Role == "acic" || req.Role == "waf-verify" || req.Role == "waf-challenge" {
		transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := transport.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("target HTTP %d", resp.StatusCode)
	}
	return resp, body, nil
}
func solve(ctx context.Context, ng *nullgate.Client, amazon, aws *http.Client, entryURL string) (int, error) {
	entry, body, err := send(ctx, amazon, &nullgate.AcicRequest{Method: "GET", URL: entryURL})
	if err != nil {
		return 0, err
	}
	setup, err := nullgate.DiscoverAcic(entry.Request.URL.String(), string(body))
	if err != nil {
		return 0, err
	}
	if setup == nil {
		return entry.StatusCode, nil
	}
	req, err := setup.Start()
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for {
		resp, html, err := send(ctx, amazon, req)
		if err != nil {
			return 0, err
		}
		state, err := nullgate.ParseAcicResult(resp.Header)
		if err != nil {
			return 0, err
		}
		if state == nil {
			return 0, fmt.Errorf("missing ACIC result")
		}
		if state.ActionType == "PASS" {
			req, err = setup.Continuation(state)
			if err != nil {
				return 0, err
			}
			final, _, err := send(ctx, amazon, req)
			if err != nil {
				return 0, err
			}
			return final.StatusCode, nil
		}
		if seen[state.ActionType] {
			return 0, fmt.Errorf("ACIC repeated stage %s", state.ActionType)
		}
		seen[state.ActionType] = true
		var answer string
		switch state.ActionType {
		case "PROOF_OF_WORK_LEVEL_3", "PROOF_OF_WORK_LEVEL_3_CHAIN_WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2":
			proof, e := ng.AcicPow(ctx, nullgate.AcicPowOptions{ChallengeType: state.ActionType, HTML: string(html)})
			if e != nil {
				return 0, e
			}
			if e = proof.Wait(ctx); e != nil {
				return 0, e
			}
			answer = proof.Response
		case "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2", "WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_3":
			waf, e := nullgate.DiscoverAcicWaf(resp.Request.URL.String(), string(html))
			if e != nil {
				return 0, e
			}
			if waf == nil || (waf.RoundsRequired != 2 && waf.RoundsRequired != 3) {
				return 0, fmt.Errorf("unsupported WAF view or round policy")
			}
			_, problem, e := send(ctx, aws, waf.Challenge())
			if e != nil {
				return 0, e
			}
			presented := time.Now()
			for range waf.RoundsRequired {
				solution, e := ng.AcicWaf(ctx, nullgate.AcicWafOptions{Problem: problem})
				if e != nil {
					return 0, e
				}
				verification, e := solution.VerificationBody(problem, time.Since(presented).Seconds(), waf.Locale)
				if e != nil {
					return 0, e
				}
				request, e := waf.Verify(problem, verification)
				if e != nil {
					return 0, e
				}
				_, result, e := send(ctx, aws, request)
				if e != nil {
					return 0, e
				}
				voucher, next, e := waf.Voucher(json.RawMessage(result))
				if e != nil {
					return 0, e
				}
				if voucher != "" {
					answer = state.VoucherResponse(voucher)
					break
				}
				problem = next
				presented = time.Now()
			}
			if answer == "" {
				return 0, fmt.Errorf("WAF returned no voucher within round policy")
			}
		default:
			return 0, fmt.Errorf("unsupported ACIC stage %s", state.ActionType)
		}
		req, err = setup.Answer(state, answer)
		if err != nil {
			return 0, err
		}
	}
}
func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: acic <fresh entry URL>")
	}
	ng, err := nullgate.NewClient("", nullgate.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer ng.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	amazon := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	aws := &http.Client{Timeout: 30 * time.Second}
	status, err := solve(context.Background(), ng, amazon, aws, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Final HTTP %d\n", status)
}
