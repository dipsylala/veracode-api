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
	appinfo   Application profile details
	apps      List application profiles
	sandboxes List sandboxes for an application
  scaninfo  Scan/build metadata (latest or specific scan)
  version   Print version and exit

Application flags (static, dynamic, sca, appinfo, sandboxes, scaninfo):
  --app string           Application profile name
                         (falls back to .veracode-workspace.json in --workspace-root)
  --workspace-root dir   Directory to search for .veracode-workspace.json (default: cwd)
  --format string        Output format: json or markdown (default json)

Findings only:
  --severity int         Exact severity (0-5)
  --severity-gte int     Minimum severity (>= value)
  --cvss float           Exact CVSS score (0-10)
  --cvss-gte float       Minimum CVSS score (>= value, 0-10)
  --status string        Comma-separated finding statuses (NEW,OPEN,FIXED,MITIGATED)
  --cwe-ids string       Comma-separated CWE IDs
  --violates-policy      Only show policy-violating findings
  --page int             Page number (default 0)
  --size int             Page size (default 100)

Apps only:
	--page int             Page number (default 0)
	--size int             Page size (default 100)

Static only:
	--sandbox string       Sandbox name or GUID
  --exclude-mitigations  Exclude mitigation annotation details

Dynamic only:
  --exclude-mitigations  Exclude mitigation annotation details

SCA only:
  --only-exploitable     Only exploitable vulnerabilities
  --only-new             Only new findings

Scan Info only:
  --build-id int         Specific build/scan ID (default: latest scan)
	--sandbox string       Sandbox name or GUID
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
	case "appinfo":
		err = runAppInfo(os.Args[2:])
	case "apps":
		err = runApps(os.Args[2:])
	case "sandboxes":
		err = runSandboxes(os.Args[2:])
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
