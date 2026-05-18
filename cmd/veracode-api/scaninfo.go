package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// scaninfoOutput wraps *api.BuildInfoOutput and implements Renderer.
type scaninfoOutput struct{ *api.BuildInfoOutput }

func (s *scaninfoOutput) WriteMarkdown(w io.Writer) error {
	out := s.BuildInfoOutput
	fmt.Fprintf(w, "# %s — Scan info\n\n", out.App)
	fmt.Fprintln(w, "| | |")
	fmt.Fprintln(w, "|:--|:--|")
	if out.ScanName != "" {
		fmt.Fprintf(w, "| Scan name | %s |\n", out.ScanName)
	}
	fmt.Fprintf(w, "| Build ID | %d |\n", out.BuildID)
	if out.Submitter != "" {
		fmt.Fprintf(w, "| Submitter | %s |\n", out.Submitter)
	}
	if out.PolicyName != "" {
		fmt.Fprintf(w, "| Policy | %s |\n", out.PolicyName)
	}
	if out.PolicyComplianceStatus != "" {
		fmt.Fprintf(w, "| Compliance | %s |\n", out.PolicyComplianceStatus)
	}
	fmt.Fprintf(w, "| Results ready | %s |\n", policyMark(out.ResultsReady))
	fmt.Fprintf(w, "| Grace period expired | %s |\n", policyMark(out.GracePeriodExpired))
	fmt.Fprintf(w, "| Scan overdue | %s |\n", policyMark(out.ScanOverdue))
	if len(out.AnalysisUnits) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "## Analysis units")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Type | Status | Engine |")
		fmt.Fprintln(w, "|:--|:--|:--|")
		for _, au := range out.AnalysisUnits {
			fmt.Fprintf(w, "| %s | %s | %s |\n", au.AnalysisType, au.Status, au.EngineVersion)
		}
	}
	return nil
}

func (s *scaninfoOutput) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

var _ Renderer = (*scaninfoOutput)(nil)

func runScanInfo(args []string) error {
	fs := flag.NewFlagSet("scaninfo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var appFlag string
	var workspaceRoot string
	var buildID int
	var sandbox string

	fs.StringVar(&appFlag, "app", "", "Application profile name")
	fs.StringVar(&workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	fs.IntVar(&buildID, "build-id", 0, "Specific build/scan ID (default: latest scan)")
	fs.StringVar(&sandbox, "sandbox", "", "Sandbox name or GUID")
	var format string
	fs.StringVar(&format, "format", "json", "Output format: json or markdown")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api scaninfo: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	return run(format, appFlag, workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		appInfo, err := c.GetAppInfo(ctx, appName)
		if err != nil {
			return nil, err
		}
		var sandboxID int
		if sandbox != "" {
			sandboxInfo, err := c.ResolveSandboxInfo(ctx, appGUID, sandbox)
			if err != nil {
				return nil, err
			}
			sandboxID = sandboxInfo.ID
		}
		out, err := c.GetBuildInfo(ctx, appName, appInfo.ID, buildID, sandboxID)
		if err != nil {
			return nil, err
		}
		return &scaninfoOutput{out}, nil
	})
}
