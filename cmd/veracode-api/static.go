package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"veracode-api/internal/api"
)

func runStatic(args []string) error {
	fs := flag.NewFlagSet("static", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var sandbox string
	var excludeMitigations bool
	var flawID string

	fs.StringVar(&sandbox, "sandbox", "", "Sandbox name")
	fs.BoolVar(&excludeMitigations, "exclude-mitigations", false, "Exclude mitigation annotation details")
	fs.StringVar(&flawID, "flaw-id", "", "Issue ID of a specific flaw to retrieve static call-stack details")

	common, err := parseCommon(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api static: %v\n", err)
		printFlagDefaults(fs)
		return nil
	}

	if flawID != "" {
		sandboxCopy := sandbox // capture for closure
		return executeDetail(common.app, common.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (any, error) {
			return c.GetStaticFlawDetail(ctx, appGUID, appName, flawID, sandboxCopy)
		})
	}

	p := buildParams(common, "STATIC")
	p.Sandbox = sandbox
	p.IncludeMitigations = !excludeMitigations

	return execute(common, p)
}
