package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
	"veracode-api/internal/credentials"
	"veracode-api/internal/workspace"
)

// bootstrap resolves credentials, looks up the app GUID, and calls fn.
func bootstrap(app, workspaceRoot string, fn func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error)) (Renderer, error) {
	appName, err := workspace.ResolveAppName(app, workspaceRoot)
	if err != nil {
		return nil, err
	}

	apiID, apiKey, baseURL, err := credentials.GetCredentials()
	if err != nil {
		return nil, err
	}

	client := api.NewClient(apiID, apiKey, baseURL)
	ctx := context.Background()

	appGUID, err := client.GetAppGUID(ctx, appName)
	if err != nil {
		return nil, err
	}

	return fn(ctx, client, appGUID, appName)
}

// Renderer is implemented by output types that support all output formats.
type Renderer interface {
	WriteJSON(w io.Writer) error
	WriteMarkdown(w io.Writer) error
}

// formatOutput writes v to stdout in the requested format.
// Returns an error for unknown formats.
func formatOutput(format string, v Renderer) error {
	switch format {
	case "json":
		return v.WriteJSON(os.Stdout)
	case "markdown":
		return v.WriteMarkdown(os.Stdout)
	default:
		return fmt.Errorf("--format must be \"json\" or \"markdown\"")
	}
}

// run bootstraps, then writes the result in the requested format.
func run(format, app, workspaceRoot string, fn func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error)) error {
	out, err := bootstrap(app, workspaceRoot, fn)
	if err != nil {
		return err
	}
	return formatOutput(format, out)
}

// writeJSON writes v as indented JSON to w.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// policyMark returns a checkmark if v is true, or an empty string.
func policyMark(v bool) string {
	if v {
		return "✓"
	}
	return ""
}

// printFlagDefaults writes flag usage to stderr (used by subcommands).
func printFlagDefaults(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "\nFlags:\n")
	fs.PrintDefaults()
}
