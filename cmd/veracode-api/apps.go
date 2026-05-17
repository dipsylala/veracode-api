package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"veracode-api/internal/api"
	"veracode-api/internal/credentials"
)

func runApps(args []string) error {
	fs := flag.NewFlagSet("apps", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var page int
	var size int

	fs.IntVar(&page, "page", 0, "Page number")
	fs.IntVar(&size, "size", 100, "Page size")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api apps: %v\n", err)
		printFlagDefaults(fs)
		return err
	}
	if page < 0 {
		fmt.Fprintf(os.Stderr, "veracode-api apps: --page must be >= 0\n")
		printFlagDefaults(fs)
		return fmt.Errorf("--page must be >= 0")
	}
	if size <= 0 {
		fmt.Fprintf(os.Stderr, "veracode-api apps: --size must be > 0\n")
		printFlagDefaults(fs)
		return fmt.Errorf("--size must be > 0")
	}

	apiID, apiKey, baseURL, err := credentials.GetCredentials()
	if err != nil {
		return err
	}

	client := api.NewClient(apiID, apiKey, baseURL)
	ctx := context.Background()

	out, err := client.GetApplications(ctx, page, size)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
