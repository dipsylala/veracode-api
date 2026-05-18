package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// dynamicOutput wraps *api.Output for dynamic findings and implements Renderer.
type dynamicOutput struct{ *api.Output }

func (d *dynamicOutput) WriteMarkdown(w io.Writer) error {
	out := d.Output
	fmt.Fprintf(w, "# %s — DYNAMIC findings\n\n", out.App)
	meta := fmt.Sprintf("**Total:** %d | **Page:** %d | **Size:** %d", out.TotalCount, out.Page, out.Size)
	if out.BuildID != 0 {
		meta += fmt.Sprintf(" | **Build:** %d", out.BuildID)
	}
	fmt.Fprintf(w, "%s\n\n", meta)
	if len(out.Findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}
	fmt.Fprintln(w, "| ID | Sev | CWE | Status | Policy | URL |")
	fmt.Fprintln(w, "|:--|:--|:--|:--|:--|:--|")
	for _, f := range out.Findings {
		fmt.Fprintf(w, "| %d | %d | %d | %s | %s | %s |\n",
			f.IssueID, f.Severity, f.CWEID, f.Status, policyMark(f.ViolatesPolicy),
			f.URL)
	}
	if hasMitigations(out.Findings) {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "## Mitigations")
		fmt.Fprintln(w)
		for _, f := range out.Findings {
			writeMitigationsMarkdown(w, f)
		}
	}
	return nil
}

func (d *dynamicOutput) WriteJSON(w io.Writer) error { return writeJSON(w, d) }

var _ Renderer = (*dynamicOutput)(nil)

// dynamicDetailOutput wraps *api.DynamicDetailOutput and implements Renderer.
type dynamicDetailOutput struct{ *api.DynamicDetailOutput }

func (d *dynamicDetailOutput) WriteMarkdown(w io.Writer) error {
	out := d.DynamicDetailOutput
	fmt.Fprintf(w, "# %s — Dynamic flaw %d\n\n", out.App, out.FlawID)
	meta := ""
	if out.CWEID != 0 {
		meta = fmt.Sprintf("**CWE:** %d", out.CWEID)
	}
	if out.URL != "" {
		if meta != "" {
			meta += " | "
		}
		meta += fmt.Sprintf("**URL:** %s", out.URL)
	}
	if out.Method != "" {
		if meta != "" {
			meta += " | "
		}
		meta += fmt.Sprintf("**Method:** %s", out.Method)
	}
	if meta != "" {
		fmt.Fprintf(w, "%s\n\n", meta)
	}
	if out.Description != "" {
		fmt.Fprintf(w, "**Description:** %s\n\n", out.Description)
	}
	if out.Recommendation != "" {
		fmt.Fprintf(w, "**Recommendation:** %s\n\n", out.Recommendation)
	}
	if len(out.AttackVectors) > 0 {
		fmt.Fprintln(w, "## Attack vectors")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Name | Type | Description |")
		fmt.Fprintln(w, "|:--|:--|:--|")
		for _, av := range out.AttackVectors {
			fmt.Fprintf(w, "| %s | %s | %s |\n", av.Name, av.Type, av.Description)
		}
		fmt.Fprintln(w)
	}
	if out.HTTPRequest != "" {
		fmt.Fprintf(w, "## HTTP Request\n\n```\n%s\n```\n\n", out.HTTPRequest)
	}
	if out.HTTPResponse != "" {
		fmt.Fprintf(w, "## HTTP Response\n\n```\n%s\n```\n\n", out.HTTPResponse)
	}
	return nil
}

func (d *dynamicDetailOutput) WriteJSON(w io.Writer) error { return writeJSON(w, d) }

var _ Renderer = (*dynamicDetailOutput)(nil)

func runDynamic(args []string) error {
	fs := flag.NewFlagSet("dynamic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var includeMitigations bool
	var flawID int

	fs.BoolVar(&includeMitigations, "include-mitigations", false, "Include mitigation details")
	fs.IntVar(&flawID, "flaw-id", 0, "Issue ID of a specific flaw to retrieve dynamic HTTP-request details")

	findings, err := parseFindings(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api dynamic: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	if flawID > 0 {
		return run(findings.format, findings.app, findings.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
			out, err := c.GetDynamicFlawDetail(ctx, appGUID, appName, flawID)
			if err != nil {
				return nil, err
			}
			return &dynamicDetailOutput{out}, nil
		})
	}

	p := buildParams(findings, "DYNAMIC")
	p.IncludeMitigations = includeMitigations

	return run(findings.format, findings.app, findings.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		out, err := c.GetFindings(ctx, appGUID, appName, p)
		if err != nil {
			return nil, err
		}
		return &dynamicOutput{out}, nil
	})
}
