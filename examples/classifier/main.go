// Classifier compares one image with labels or independent text queries.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nullgate-club/nullgate-sdk-go/v2"
	"github.com/nullgate-club/nullgate-sdk-go/v2/api"
	"github.com/nullgate-club/nullgate-sdk-go/v2/classifier"
)

func run() error {
	if len(os.Args) < 5 || (os.Args[1] != "classify" && os.Args[1] != "match") {
		return fmt.Errorf("usage: %s classify|match IMAGE TEXT TEXT [TEXT ...]", os.Args[0])
	}
	image, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	client, err := nullgate.New("", api.Options{})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Args[1] == "classify" {
		result, err := client.Classifier.Classify(ctx, classifier.ClassifyOptions{Images: [][]byte{image}, Labels: os.Args[3:], Model: classifier.Balanced})
		if err != nil {
			return err
		}
		fmt.Printf("Best label: %s\n", result.Results[0].Label)
		return nil
	}
	result, err := client.Classifier.Match(ctx, classifier.MatchOptions{Images: [][]byte{image}, Queries: os.Args[3:]})
	if err != nil {
		return err
	}
	for i, score := range result.Results[0].Scores {
		fmt.Printf("%s: %.6f\n", os.Args[i+3], score)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
