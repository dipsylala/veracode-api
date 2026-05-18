package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// appinfoOutput wraps *api.ApplicationDetailOutput and implements Renderer.
type appinfoOutput struct{ *api.ApplicationDetailOutput }

func (a *appinfoOutput) WriteMarkdown(w io.Writer) error {
	out := a.ApplicationDetailOutput
	fmt.Fprintf(w, "# %s\n\n", out.Name)
	fmt.Fprintln(w, "| Field | Value |")
	fmt.Fprintln(w, "|:--|:--|")
	fmt.Fprintf(w, "| GUID | `%s` |\n", out.GUID)
	fmt.Fprintf(w, "| ID | %d |\n", out.ID)
	if profile, ok := out.Application["profile"].(map[string]any); ok {
		if bc, ok := profile["business_criticality"].(string); ok && bc != "" {
			fmt.Fprintf(w, "| Business criticality | %s |\n", bc)
		}
		if policies, ok := profile["policies"].([]any); ok && len(policies) > 0 {
			if p, ok := policies[0].(map[string]any); ok {
				if name, ok := p["name"].(string); ok && name != "" {
					fmt.Fprintf(w, "| Policy | %s |\n", name)
				}
				if status, ok := p["policy_compliance_status"].(string); ok && status != "" {
					fmt.Fprintf(w, "| Compliance | %s |\n", status)
				}
			}
		}
	}
	if created, ok := out.Application["created"].(string); ok && created != "" {
		fmt.Fprintf(w, "| Created | %s |\n", created)
	}
	if lastScan, ok := out.Application["last_completed_scan_date"].(string); ok && lastScan != "" {
		fmt.Fprintf(w, "| Last scan | %s |\n", lastScan)
	}
	return nil
}

func (a *appinfoOutput) WriteJSON(w io.Writer) error { return writeJSON(w, a) }

var _ Renderer = (*appinfoOutput)(nil)

func runAppInfo(args []string) error {
	fs := flag.NewFlagSet("appinfo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var appFlag string
	var workspaceRoot string

	fs.StringVar(&appFlag, "app", "", "Application profile name")
	fs.StringVar(&workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	var format string
	fs.StringVar(&format, "format", "json", "Output format: json or markdown")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api appinfo: %v\n", err)
		printFlagDefaults(fs)
		return err
	}
	return run(format, appFlag, workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		out, err := c.GetApplicationDetails(ctx, appGUID, appName)
		if err != nil {
			return nil, err
		}
		return &appinfoOutput{out}, nil
	})
}
