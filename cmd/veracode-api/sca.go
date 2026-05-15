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
		return nil
	}

	fs.Visit(func(flg *flag.Flag) {
		switch flg.Name {
		case "severity-gte":
			severityGteSet = true
		case "cvss-gte":
			cvssGteSet = true
		}
	})

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
