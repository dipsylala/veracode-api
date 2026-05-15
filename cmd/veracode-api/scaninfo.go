package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"veracode-api/internal/api"
	"veracode-api/internal/credentials"
	"veracode-api/internal/workspace"
)

func runScanInfo(args []string) error {
	fs := flag.NewFlagSet("scaninfo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var appFlag string
	var workspaceRoot string
	var buildID int

	fs.StringVar(&appFlag, "app", "", "Application profile name")
	fs.StringVar(&workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	fs.IntVar(&buildID, "build-id", 0, "Specific build/scan ID (default: latest scan)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api scaninfo: %v\n", err)
		printFlagDefaults(fs)
		return nil
	}

	appName, err := workspace.ResolveAppName(appFlag, workspaceRoot)
	if err != nil {
		return err
	}

	apiID, apiKey, baseURL, err := credentials.GetCredentials()
	if err != nil {
		return err
	}

	client := api.NewClient(apiID, apiKey, baseURL)
	ctx := context.Background()

	appInfo, err := client.GetAppInfo(ctx, appName)
	if err != nil {
		return err
	}

	out, err := client.GetBuildInfo(ctx, appName, appInfo.ID, buildID)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
