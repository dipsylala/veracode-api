package main

import (
	"flag"
	"fmt"
	"os"
)

func runSCA(args []string) error {
	fs := flag.NewFlagSet("sca", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var severityGte int
	var severityGteSet bool
	var cvssGte float64
	var cvssGteSet bool
	var onlyExploitable bool
	var onlyNew bool

	fs.IntVar(&severityGte, "severity-gte", -1, "Minimum severity (>= value, 0-5)")
	fs.Float64Var(&cvssGte, "cvss-gte", -1, "Minimum CVSS score")
	fs.BoolVar(&onlyExploitable, "only-exploitable", false, "Only exploitable vulnerabilities")
	fs.BoolVar(&onlyNew, "only-new", false, "Only new findings")

	common, err := parseCommon(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veracode-api sca: %v\n", err)
		printFlagDefaults(fs)
		return err
	}

	fs.Visit(func(flg *flag.Flag) {
		switch flg.Name {
		case "severity-gte":
			severityGteSet = true
		case "cvss-gte":
			cvssGteSet = true
		}
	})

	if severityGteSet && (severityGte < 0 || severityGte > 5) {
		fmt.Fprintf(os.Stderr, "veracode-api sca: --severity-gte must be between 0 and 5\n")
		printFlagDefaults(fs)
		return fmt.Errorf("--severity-gte must be between 0 and 5")
	}
	if cvssGteSet && (cvssGte < 0.0 || cvssGte > 10.0) {
		fmt.Fprintf(os.Stderr, "veracode-api sca: --cvss-gte must be between 0.0 and 10.0\n")
		printFlagDefaults(fs)
		return fmt.Errorf("--cvss-gte must be between 0.0 and 10.0")
	}

	p := buildParams(common, "SCA")
	p.OnlyExploitable = onlyExploitable
	p.OnlyNew = onlyNew

	if severityGteSet {
		p.SeverityGte = &severityGte
	}
	if cvssGteSet {
		p.CvssGte = &cvssGte
	}

	return execute(common, p)
}
