package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
// Falls back to "dev" for local builds.
var version = "dev"

const usage = `Usage: veracode-api <domain> [flags]

Domains:
  static    SAST (static analysis) findings
  dynamic   DAST (dynamic analysis) findings
  sca       SCA component vulnerability findings
  scaninfo  Scan/build metadata (latest or specific scan)
  version   Print version and exit

Common flags:
  --app string           Application profile name
                         (falls back to .veracode-workspace.json in --workspace-root)
  --workspace-root dir   Directory to search for .veracode-workspace.json (default: cwd)
  --severity int         Exact severity filter (0-5)
  --status string        Comma-separated finding statuses (NEW,OPEN,FIXED,MITIGATED)
  --cwe-ids string       Comma-separated CWE IDs
  --violates-policy      Only show policy-violating findings
  --page int             Page number (default 0)
  --size int             Page size (default 100)

Static / Dynamic only:
  --sandbox string       Sandbox name
  --exclude-mitigations  Exclude mitigation annotation details

SCA only:
  --severity-gte int     Minimum severity (>= value)
  --cvss-gte float       Minimum CVSS score
  --only-exploitable     Only exploitable vulnerabilities
  --only-new             Only new findings

Scan Info only:
  --build-id int         Specific build/scan ID (default: latest scan)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "static":
		err = runStatic(os.Args[2:])
	case "dynamic":
		err = runDynamic(os.Args[2:])
	case "sca":
		err = runSCA(os.Args[2:])
	case "scaninfo":
		err = runScanInfo(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Println(version)
	case "--help", "-h", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown domain: %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
