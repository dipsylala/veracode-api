package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"veracode-api/internal/api"
)

func runDynamic(args []string) error {
	fs := flag.NewFlagSet("dynamic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var excludeMitigations bool
	var flawID int

	fs.BoolVar(&excludeMitigations, "exclude-mitigations", false, "Exclude mitigation annotation details")
	fs.IntVar(&flawID, "flaw-id", 0, "Issue ID of a specific flaw to retrieve dynamic HTTP-request details")

	common, err := parseCommon(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api dynamic: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	if flawID > 0 {
		return executeDetail(common.app, common.workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (any, error) {
			return c.GetDynamicFlawDetail(ctx, appGUID, appName, flawID)
		})
	}

	p := buildParams(common, "DYNAMIC")
	p.IncludeMitigations = !excludeMitigations

	return execute(common, p)
}
