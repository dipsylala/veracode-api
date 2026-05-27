package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"veracode-api/internal/api"
	"veracode-api/internal/credentials"
)

// appsOutput wraps *api.ApplicationListOutput and implements Renderer.
type appsOutput struct{ *api.ApplicationListOutput }

func (a *appsOutput) WriteMarkdown(w io.Writer) error {
	out := a.ApplicationListOutput
	fmt.Fprintf(w, "# Applications\n\n")
	meta := findingsMetadata(int64(out.TotalApplications), out.Page, out.Size, 0)
	fmt.Fprintf(w, "%s\n\n", meta)
	if len(out.Applications) == 0 {
		fmt.Fprintln(w, "_No applications._")
		return nil
	}
	fmt.Fprintln(w, "| Name | ID | GUID |")
	fmt.Fprintln(w, "|:--|--:|:--|")
	for _, app := range out.Applications {
		fmt.Fprintf(w, "| %s | %d | %s |\n", app.Name, app.ID, app.GUID)
	}
	return nil
}

func (a *appsOutput) WriteJSON(w io.Writer) error { return writeJSON(w, a) }

var _ Renderer = (*appsOutput)(nil)

func runApps(args []string) error {
	fs := flag.NewFlagSet("apps", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var page int
	var size int

	var allResults bool
	fs.BoolVar(&allResults, "all-results", false, "Fetch all pages, ignoring --page and --size")
	fs.IntVar(&page, "page", 0, "Page number")
	fs.IntVar(&size, "size", 100, "Page size")
	var format string
	fs.StringVar(&format, "format", "json", "Output format: json or markdown")

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
	if !allResults && size <= 0 {
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

	var out *api.ApplicationListOutput
	if allResults {
		out, err = client.GetAllApplications(ctx)
	} else {
		out, err = client.GetApplications(ctx, page, size)
	}
	if err != nil {
		return err
	}

	return formatOutput(format, &appsOutput{out})
}
