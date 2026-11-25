// Command solve calls the local HTTP API with the caller's target identity.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/nullgate-club/nullgate-sdk-go/v2/solver"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	url, userAgent := os.Getenv("TARGET_URL"), os.Getenv("TARGET_USER_AGENT")
	if url == "" || userAgent == "" {
		return fmt.Errorf("TARGET_URL and TARGET_USER_AGENT are required")
	}
	client, err := solver.New(solver.Options{})
	if err != nil {
		return err
	}
	result, err := client.Solve(context.Background(), solver.Request{
		Type:      solver.Akamai,
		URL:       url,
		UserAgent: userAgent,
		Proxy:     os.Getenv("TARGET_PROXY"),
		Session:   os.Getenv("TARGET_SESSION"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("Received %d cookies\n", len(result.Cookies))
	return nil
}
