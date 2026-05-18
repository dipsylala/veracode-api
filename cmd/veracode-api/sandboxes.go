package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
)

// sandboxesOutput wraps *api.SandboxListOutput and implements Renderer.
type sandboxesOutput struct{ *api.SandboxListOutput }

func (s *sandboxesOutput) WriteMarkdown(w io.Writer) error {
	out := s.SandboxListOutput
	fmt.Fprintf(w, "# %s — Sandboxes\n\n", out.App)
	fmt.Fprintf(w, "**Total:** %d\n\n", out.TotalSandboxes)
	if len(out.Sandboxes) == 0 {
		fmt.Fprintln(w, "_No sandboxes._")
		return nil
	}
	fmt.Fprintln(w, "| Name | ID | GUID |")
	fmt.Fprintln(w, "|:--|--:|:--|")
	for _, sb := range out.Sandboxes {
		fmt.Fprintf(w, "| %s | %d | %s |\n", sb.Name, sb.ID, sb.GUID)
	}
	return nil
}

func (s *sandboxesOutput) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

var _ Renderer = (*sandboxesOutput)(nil)

func runSandboxes(args []string) error {
	fs := flag.NewFlagSet("sandboxes", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var appFlag string
	var workspaceRoot string

	fs.StringVar(&appFlag, "app", "", "Application profile name")
	fs.StringVar(&workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	var format string
	fs.StringVar(&format, "format", "json", "Output format: json or markdown")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api sandboxes: %v\n", err)
		printFlagDefaults(fs)
		return err
	}
	return run(format, appFlag, workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
		out, err := c.GetSandboxList(ctx, appGUID, appName)
		if err != nil {
			return nil, err
		}
		return &sandboxesOutput{out}, nil
	})
}
