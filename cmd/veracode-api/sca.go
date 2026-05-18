package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// scaOutput wraps *api.Output for SCA findings and implements Renderer.
type scaOutput struct{ *api.Output }

func (s *scaOutput) WriteMarkdown(w io.Writer) error {
	out := s.Output
	fmt.Fprintf(w, "# %s — SCA findings\n\n", out.App)
	fmt.Fprintf(w, "**Total:** %d | **Page:** %d | **Size:** %d\n\n", out.TotalCount, out.Page, out.Size)
	if len(out.Findings) == 0 {
		fmt.Fprintln(w, "_No findings._")
		return nil
	}
	fmt.Fprintln(w, "| Sev | CVSS | CVE | Component | Version | Status | Policy |")
	fmt.Fprintln(w, "|:--|:--|:--|:--|:--|:--|:--|")
	for _, f := range out.Findings {
		cvss := ""
		if f.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f", f.CVSS)
		}
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s |\n",
			f.Severity, cvss, f.CVE, f.Component, f.Version,
			f.Status, policyMark(f.ViolatesPolicy))
	}
	fmt.Fprintln(w)
	for _, f := range out.Findings {
		heading := fmt.Sprintf("### severity %d", f.Severity)
		if f.CVE != "" {
			heading += " · " + f.CVE
		}
		fmt.Fprintln(w, heading)
		if f.Component != "" {
			fmt.Fprintf(w, "**Component:** %s %s  \n", f.Component, f.Version)
		}
		if f.CVSS > 0 {
			fmt.Fprintf(w, "**CVSS:** %.1f  \n", f.CVSS)
		}
		if f.Description != "" {
			fmt.Fprintf(w, "\n%s\n\n", f.Description)
		} else {
			fmt.Fprintln(w)
		}
	}
	return nil
}

func (s *scaOutput) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

var _ Renderer = (*scaOutput)(nil)

func runSCA(args []string) error {
	fs := flag.NewFlagSet("sca", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var onlyExploitable bool

	fs.BoolVar(&onlyExploitable, "only-exploitable", false, "Only exploitable vulnerabilities")

	findings, err := parseFindings(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api sca: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	p := buildParams(findings, "SCA")
	p.OnlyExploitable = onlyExploitable

	return run(findings.format, findings.app, findings.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		out, err := c.GetFindings(ctx, appGUID, appName, p)
		if err != nil {
			return nil, err
		}
		return &scaOutput{out}, nil
	})
}
