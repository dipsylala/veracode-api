package main

import (
	"flag"
	"fmt"
	"strings"

	"veracode-api/internal/api"
)

// findingsFlags holds flags shared by all three findings domains (static, dynamic, sca).
type findingsFlags struct {
	app            string
	workspaceRoot  string
	severity       int
	severitySet    bool
	severityGte    int
	severityGteSet bool
	cvss           float64
	cvssSet        bool
	cvssGte        float64
	cvssGteSet     bool
	status         string
	cweIDs         string
	violatesPolicy bool
	page           int
	size           int
	format         string
}

// parseFindings registers and parses the flags that apply to every findings domain.
func parseFindings(fs *flag.FlagSet, args []string) (findingsFlags, error) {
	var f findingsFlags
	fs.StringVar(&f.app, "app", "", "Application profile name")
	fs.StringVar(&f.workspaceRoot, "workspace-root", "", "Directory containing .veracode-workspace.json")
	fs.IntVar(&f.severity, "severity", -1, "Exact severity (0-5)")
	fs.IntVar(&f.severityGte, "severity-gte", -1, "Minimum severity (0-5)")
	fs.Float64Var(&f.cvss, "cvss", -1, "Exact CVSS score (0-10)")
	fs.Float64Var(&f.cvssGte, "cvss-gte", -1, "Minimum CVSS score (>= value, 0-10)")
	fs.StringVar(&f.status, "status", "", "Comma-separated finding statuses")
	fs.StringVar(&f.cweIDs, "cwe-ids", "", "Comma-separated CWE IDs")
	fs.BoolVar(&f.violatesPolicy, "violates-policy", false, "Only policy-violating findings")
	fs.IntVar(&f.page, "page", 0, "Page number")
	fs.IntVar(&f.size, "size", 100, "Page size")
	fs.StringVar(&f.format, "format", "json", "Output format: json or markdown")

	if err := fs.Parse(args); err != nil {
		return f, err
	}

	// Detect whether filter flags were explicitly provided
	fs.Visit(func(flg *flag.Flag) {
		switch flg.Name {
		case "severity":
			f.severitySet = true
		case "severity-gte":
			f.severityGteSet = true
		case "cvss":
			f.cvssSet = true
		case "cvss-gte":
			f.cvssGteSet = true
		}
	})

	if f.severitySet && (f.severity < 0 || f.severity > 5) {
		return f, fmt.Errorf("--severity must be between 0 and 5")
	}
	if f.severityGteSet && (f.severityGte < 0 || f.severityGte > 5) {
		return f, fmt.Errorf("--severity-gte must be between 0 and 5")
	}
	if f.cvssSet && (f.cvss < 0 || f.cvss > 10) {
		return f, fmt.Errorf("--cvss must be between 0 and 10")
	}
	if f.cvssGteSet && (f.cvssGte < 0 || f.cvssGte > 10) {
		return f, fmt.Errorf("--cvss-gte must be between 0 and 10")
	}
	if f.page < 0 {
		return f, fmt.Errorf("--page must be >= 0")
	}
	if f.size <= 0 {
		return f, fmt.Errorf("--size must be > 0")
	}
	return f, nil
}

// buildParams converts parsed flags to a FindingsParams.
func buildParams(f findingsFlags, scanType string) api.FindingsParams {
	p := api.FindingsParams{
		ScanType: scanType,
		Page:     f.page,
		Size:     f.size,
	}
	if f.severitySet {
		p.Severity = &f.severity
	}
	if f.severityGteSet {
		p.SeverityGte = &f.severityGte
	}
	if f.cvssSet {
		p.Cvss = &f.cvss
	}
	if f.cvssGteSet {
		p.CvssGte = &f.cvssGte
	}
	if f.status != "" {
		p.Status = strings.Split(f.status, ",")
	}
	if f.cweIDs != "" {
		p.CWEIDs = strings.Split(f.cweIDs, ",")
	}
	if f.violatesPolicy {
		t := true
		p.ViolatesPolicy = &t
	}
	return p
}
