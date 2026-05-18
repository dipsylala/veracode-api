package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// staticOutput wraps *api.Output for static findings and implements Renderer.
type staticOutput struct{ *api.Output }

func (s *staticOutput) WriteMarkdown(w io.Writer) error {
	out := s.Output
	fmt.Fprintf(w, "# %s — STATIC findings\n\n", out.App)
	meta := fmt.Sprintf("**Total:** %d | **Page:** %d | **Size:** %d", out.TotalCount, out.Page, out.Size)
	if out.BuildID != 0 {
		meta += fmt.Sprintf(" | **Build:** %d", out.BuildID)
	}
	fmt.Fprintf(w, "%s\n\n", meta)
	if len(out.Findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}
	fmt.Fprintln(w, "| ID | Sev | CWE | Status | Policy | File | Line | Attack Vector |")
	fmt.Fprintln(w, "|:--|:--|:--|:--|:--|:--|--:|:--|")
	for _, f := range out.Findings {
		fmt.Fprintf(w, "| %d | %d | %d | %s | %s | %s | %d | %s |\n",
			f.IssueID, f.Severity, f.CWEID, f.Status, policyMark(f.ViolatesPolicy),
			f.FileName, f.LineNumber, f.AttackVector)
	}
	fmt.Fprintln(w)
	for _, f := range out.Findings {
		fmt.Fprintf(w, "### Finding %d · severity %d · CWE-%d\n", f.IssueID, f.Severity, f.CWEID)
		if f.FilePath != "" {
			fmt.Fprintf(w, "**Location:** %s:%d", f.FilePath, f.LineNumber)
			if f.Module != "" {
				fmt.Fprintf(w, " · **Module:** %s", f.Module)
			}
			fmt.Fprintln(w, "  ")
		}
		if f.AttackVector != "" {
			fmt.Fprintf(w, "**Attack vector:** %s  \n", f.AttackVector)
		}
		fmt.Fprintln(w)
		writeMitigationsMarkdown(w, f)
	}
	return nil
}

func (s *staticOutput) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

var _ Renderer = (*staticOutput)(nil)

// staticDetailOutput wraps *api.StaticDetailOutput and implements Renderer.
type staticDetailOutput struct{ *api.StaticDetailOutput }

func (s *staticDetailOutput) WriteMarkdown(w io.Writer) error {
	out := s.StaticDetailOutput
	fmt.Fprintf(w, "# %s — Static flaw %d\n\n", out.App, out.FlawID)
	if len(out.DataPaths) == 0 {
		fmt.Fprintln(w, "_No data paths._")
		return nil
	}
	for _, dp := range out.DataPaths {
		fmt.Fprintf(w, "## Path %d · %d steps", dp.PathIndex, dp.TotalSteps)
		if dp.Module != "" {
			fmt.Fprintf(w, " · %s", dp.Module)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Step | Type | File | Line | Function |")
		fmt.Fprintln(w, "|--:|:--|:--|:--|:--|")
		for _, c := range dp.Calls {
			line := "unknown"
			if c.LineNumber != 0 {
				line = fmt.Sprintf("%d", c.LineNumber)
			}
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s |\n",
				c.Step, c.Type, c.FileName, line, c.FunctionName)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func (s *staticDetailOutput) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

var _ Renderer = (*staticDetailOutput)(nil)

func runStatic(args []string) error {
	fs := flag.NewFlagSet("static", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var sandbox string
	var includeMitigations bool
	var flawID int

	fs.StringVar(&sandbox, "sandbox", "", "Sandbox name or GUID")
	fs.BoolVar(&includeMitigations, "include-mitigations", false, "Include mitigation details")
	fs.IntVar(&flawID, "flaw-id", 0, "Issue ID of a specific flaw to retrieve static call-stack details")

	findings, err := parseFindings(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api static: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	if flawID > 0 {
		sandboxCopy := sandbox // capture for closure
		return run(findings.format, findings.app, findings.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
			out, err := c.GetStaticFlawDetail(ctx, appGUID, appName, flawID, sandboxCopy)
			if err != nil {
				return nil, err
			}
			return &staticDetailOutput{out}, nil
		})
	}

	p := buildParams(findings, "STATIC")
	p.Sandbox = sandbox
	p.IncludeMitigations = includeMitigations

	return run(findings.format, findings.app, findings.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		out, err := c.GetFindings(ctx, appGUID, appName, p)
		if err != nil {
			return nil, err
		}
		return &staticOutput{out}, nil
	})
}
