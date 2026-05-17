package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"veracode-api/internal/api"
)

func runAppInfo(args []string) error {
	fs := flag.NewFlagSet("appinfo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var appFlag string
	var workspaceRoot string

	fs.StringVar(&appFlag, "app", "", "Application profile name")
	fs.StringVar(&workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api appinfo: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	return executeDetail(appFlag, workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (any, error) {
		return c.GetApplicationDetails(ctx, appGUID, appName)
	})
}
