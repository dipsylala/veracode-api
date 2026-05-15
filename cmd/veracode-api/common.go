package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"veracode-api/internal/api"
	"veracode-api/internal/credentials"
	"veracode-api/internal/workspace"
)

// commonFlags holds flags shared by all three domains.
type commonFlags struct {
	app            string
	workspaceRoot  string
	severity       int
	severitySet    bool
	status         string
	cweIDs         string
	violatesPolicy bool
	page           int
	size           int
}

// parseCommon registers and parses the flags that apply to every domain.
func parseCommon(fs *flag.FlagSet, args []string) (commonFlags, error) {
	var f commonFlags
	fs.StringVar(&f.app, "app", "", "Application profile name")
	fs.StringVar(&f.workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	fs.IntVar(&f.severity, "severity", -1, "Exact severity (0-5)")
	fs.StringVar(&f.status, "status", "", "Comma-separated finding statuses")
	fs.StringVar(&f.cweIDs, "cwe-ids", "", "Comma-separated CWE IDs")
	fs.BoolVar(&f.violatesPolicy, "violates-policy", false, "Only policy-violating findings")
	fs.IntVar(&f.page, "page", 0, "Page number")
	fs.IntVar(&f.size, "size", 100, "Page size")

	if err := fs.Parse(args); err != nil {
		return f, err
	}

	// Detect whether --severity was explicitly provided
	fs.Visit(func(flg *flag.Flag) {
		if flg.Name == "severity" {
			f.severitySet = true
		}
	})
	return f, nil
}

// buildParams converts parsed flags to a FindingsParams, applying common fields.
func buildParams(f commonFlags, scanType string) api.FindingsParams {
	p := api.FindingsParams{
		ScanType: scanType,
		Page:     f.page,
		Size:     f.size,
	}
	if f.severitySet {
		p.Severity = &f.severity
	}
	if f.status != "" {
		p.Status = strings.Split(f.status, ",")
	}
	if f.cweIDs != "" {
		p.CWEIDs = strings.Split(f.cweIDs, ",")
	}
	if f.violatesPolicy {
		t := true
		p.ViolatesPolicy = &t
	}
	return p
}

// execute resolves credentials, looks up the app GUID, fetches findings, and writes JSON.
func execute(f commonFlags, p api.FindingsParams) error {
	return executeDetail(f.app, f.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (any, error) {
		return c.GetFindings(ctx, appGUID, appName, p)
	})
}

// executeDetail is the shared bootstrap for all subcommands: resolve app name and
// credentials, create a client, look up the app GUID, call fn, then write JSON.
func executeDetail(app, workspaceRoot string, fn func(ctx context.Context, c *api.Client, appGUID, appName string) (any, error)) error {
	appName, err := workspace.ResolveAppName(app, workspaceRoot)
	if err != nil {
		return err
	}

	apiID, apiKey, baseURL, err := credentials.GetCredentials()
	if err != nil {
		return err
	}

	client := api.NewClient(apiID, apiKey, baseURL)
	ctx := context.Background()

	appGUID, err := client.GetAppGUID(ctx, appName)
	if err != nil {
		return err
	}

	out, err := fn(ctx, client, appGUID, appName)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// printFlagDefaults writes flag usage to stderr (used by subcommands).
func printFlagDefaults(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "\nFlags:\n")
	fs.PrintDefaults()
}
