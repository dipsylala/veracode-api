# veracode-api

A single-binary CLI for querying Veracode platform findings and metadata (SAST, DAST, SCA, applications, sandboxes, scan info) via the Veracode REST and XML APIs. No runtime dependencies — just build and run.

## Quick Start

Create `~/.veracode/veracode.yml` with your Veracode API credentials:

```yaml
api:
  key-id: "your-api-id"
  key-secret: "your-api-key"
```

You can also use environment variables; see [Authentication](#authentication).

List applications, inspect one application, and fetch scan data:

```bash
veracode-api apps
veracode-api appinfo --app "Verademo"
veracode-api static --app "Verademo" --violates-policy
veracode-api scaninfo --app "Verademo"
```

## Build

Requires Go 1.22+.

```bash
go build -o veracode-api ./cmd/veracode-api
# Windows
go build -o veracode-api.exe ./cmd/veracode-api
```

## Authentication

Credentials are loaded in priority order:

1. **`~/.veracode/veracode.yml`**

   ```yaml
   api:
     key-id: "your-api-id"
     key-secret: "your-api-key"
     override-api-base-url: ""   # optional — omit for auto-detection
   ```

2. **Environment variables**

   ```bash
   VERACODE_API_ID=your-api-id
   VERACODE_API_KEY=your-api-key
   VERACODE_OVERRIDE_API_BASE_URL=   # optional
   ```

The base URL is auto-detected from the key prefix: keys beginning with `vera01ei-` use `https://api.veracode.eu`, all others use `https://api.veracode.com`.

## Application name

Pass the Veracode application profile name with `--app`, or omit it to read from `.veracode-workspace.json` in the workspace root:

```json
{ "name": "MyApplicationProfile" }
```

Use `--workspace-root` to specify the directory containing that file (defaults to the current working directory).

## API usage

The CLI uses the Veracode REST APIs for application lookup, application listing, findings, and sandbox listing. It uses the Veracode XML API for `scaninfo`.

When you pass `--sandbox` to `static` or `scaninfo`, the CLI accepts either a sandbox name or a sandbox GUID and resolves it automatically. Omitting `--sandbox` uses the latest policy scan context for that application. Dynamic scans do not use sandboxes.

## Usage

```text
veracode-api <domain> [flags]
```

### Domains

| Domain | Description |
| --- | --- |
| `apps` | List application profiles |
| `appinfo` | Application profile details |
| `sandboxes` | List sandboxes for an application |
| `static` | SAST findings from the latest policy scan |
| `dynamic` | DAST findings from the latest policy scan |
| `sca` | SCA component vulnerability findings |
| `scaninfo` | Scan/build metadata for an application |

### Application flags (`static`, `dynamic`, `sca`, `appinfo`, `sandboxes`, `scaninfo`)

| Flag | Default | Description |
| --- | --- | --- |
| `--app string` | | Application profile name |
| `--workspace-root dir` | cwd | Directory containing `.veracode-workspace.json` |

### Apps flags (`apps`)

| Flag | Default | Description |
| --- | --- | --- |
| `--page int` | 0 | Page number |
| `--size int` | 100 | Page size |

### Findings flags (`static`, `dynamic`, `sca`)

| Flag | Default | Description |
| --- | --- | --- |
| `--severity int` | | Exact severity filter (0 = informational … 5 = very high) |
| `--status string` | | Comma-separated statuses: `NEW`, `OPEN`, `FIXED`, `MITIGATED` |
| `--cwe-ids string` | | Comma-separated CWE IDs |
| `--violates-policy` | false | Only policy-violating findings |
| `--page int` | 0 | Page number |
| `--size int` | 100 | Page size |

### Static flags

| Flag | Default | Description |
| --- | --- | --- |
| `--sandbox string` | | Sandbox name or GUID (omit for policy scan) |
| `--exclude-mitigations` | false | Exclude mitigation annotation details |
| `--flaw-id int` | | Return call-stack data paths for a specific finding |

### Dynamic flags

| Flag | Default | Description |
| --- | --- | --- |
| `--exclude-mitigations` | false | Exclude mitigation annotation details |
| `--flaw-id int` | | Return HTTP request/response details for a specific finding |

### SCA flags

| Flag | Default | Description |
| --- | --- | --- |
| `--severity-gte int` | | Minimum severity (inclusive) |
| `--cvss-gte float` | | Minimum CVSS score (inclusive) |
| `--only-exploitable` | false | Only exploitable vulnerabilities |
| `--only-new` | false | Only new findings |

### Scan Info flags

| Flag | Default | Description |
| --- | --- | --- |
| `--build-id int` | 0 | Specific build/scan ID (0 = latest scan) |
| `--sandbox string` | | Sandbox name or GUID |

## Examples

```bash
# All high/very-high SAST findings that violate policy
veracode-api static --app "MyApp" --severity 4 --violates-policy

# New DAST findings, first 25
veracode-api dynamic --app "MyApp" --status "NEW" --size 25

# SCA findings with CVSS >= 7
veracode-api sca --app "MyApp" --cvss-gte 7.0

# Call-stack detail for a specific static finding
veracode-api static --app "MyApp" --flaw-id 12345

# HTTP request/response detail for a specific dynamic finding
veracode-api dynamic --app "MyApp" --flaw-id 12345

# Using workspace config instead of --app
veracode-api static --workspace-root /path/to/project --status "NEW,OPEN"

# List application profiles
veracode-api apps

# List the first 25 application profiles
veracode-api apps --size 25

# Get application profile details
veracode-api appinfo --app "Verademo"

# List sandboxes for an application
veracode-api sandboxes --app "MyApp"

# Latest scan metadata
veracode-api scaninfo --app "MyApp"

# Latest sandbox scan metadata
veracode-api scaninfo --app "MyApp" --sandbox "Project Security"

# Specific scan metadata
veracode-api scaninfo --app "MyApp" --build-id 12345678
```

## Output

All commands write a JSON object to stdout and exit 0 on success, or print an error to stderr and exit 1.

**Findings list** (`static`, `dynamic`, `sca`):

```json
{
  "success": true,
  "app": "MyApp",
  "domain": "static",
  "total_count": 42,
  "page": 0,
  "size": 100,
  "findings": [
    {
      "issue_id": 12345,
      "scan_type": "STATIC",
      "severity": 4,
      "cwe_id": 89,
      "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
      "status": "OPEN",
      "resolution": "",
      "violates_policy": true,
      "file_path": "src/main/java/com/example/Dao.java",
      "line_number": 42,
      "module": "app.war"
    }
  ]
}
```

**Scan info** (`scaninfo`):

```json
{
  "success": true,
  "app": "MyApp",
  "app_id": 1234567,
  "build_id": 29079161,
  "scan_name": "15 Sep 2023 Static",
  "submitter": "Veracode",
  "platform": "Not Specified",
  "lifecycle_stage": "Not Specified",
  "results_ready": true,
  "policy_name": "Veracode Recommended Very High",
  "policy_compliance_status": "Did Not Pass",
  "policy_updated_date": "2023-09-15T05:22:14-04:00",
  "rules_status": "Did Not Pass",
  "grace_period_expired": true,
  "scan_overdue": true,
  "analysis_units": [
    {
      "analysis_type": "Static",
      "status": "Results Ready",
      "engine_version": "20230905230425"
    }
  ]
}
```

**Sandboxes** (`sandboxes`):

```json
{
  "success": true,
  "app": "MyApp",
  "total_sandboxes": 2,
  "sandboxes": [
    {
      "guid": "11111111-1111-1111-1111-111111111111",
      "id": 12345,
      "name": "Project Security"
    }
  ]
}
```

**Applications** (`apps`):

```json
{
  "success": true,
  "total_applications": 2,
  "page": 0,
  "size": 100,
  "applications": [
    {
      "guid": "22222222-2222-2222-2222-222222222222",
      "id": 1234567,
      "name": "MyApp"
    }
  ]
}
```

**Application info** (`appinfo`):

```json
{
  "success": true,
  "app": "Verademo",
  "guid": "22222222-2222-2222-2222-222222222222",
  "id": 1234567,
  "name": "Verademo",
  "application": {
    "guid": "22222222-2222-2222-2222-222222222222",
    "id": 1234567,
    "created": "2024-01-15T14:57:35.000Z",
    "last_completed_scan_date": "2024-02-20T09:20:53.000Z",
    "profile": {
      "name": "Verademo",
      "business_criticality": "VERY_HIGH"
    },
    "scans": [
      {
        "scan_type": "STATIC",
        "status": "PUBLISHED"
      }
    ]
  }
}
```

**Static flaw detail** (`static --flaw-id`):

```json
{
  "success": true,
  "app": "MyApp",
  "domain": "static",
  "flaw_id": 12345,
  "data_paths": [
    {
      "path_index": 1,
      "module": "app.war",
      "total_steps": 3,
      "calls": [
        { "step": 1, "type": "source",      "file_name": "Input.java",  "function_name": "getParam",   "line_number": 10 },
        { "step": 2, "type": "propagation", "file_name": "Service.java","function_name": "process",    "line_number": 55 },
        { "step": 3, "type": "sink",        "file_name": "Dao.java",    "function_name": "executeQuery","line_number": 42 }
      ]
    }
  ]
}
```

**Dynamic flaw detail** (`dynamic --flaw-id`):

```json
{
  "success": true,
  "app": "MyApp",
  "domain": "dynamic",
  "flaw_id": 12345,
  "cwe_id": 526,
  "description": "...",
  "recommendation": "...",
  "url": "https://example.com/api/endpoint",
  "method": "GET",
  "attack_vectors": [
    { "name": "Server: Apache/2.4", "type": "HEADER", "description": "banner" }
  ],
  "http_request": "GET /api/endpoint HTTP/1.1\r\n...",
  "http_response": "200 OK\r\n..."
}
```

## Severity scale

| Value | Label |
| --- | --- |
| 0 | Informational |
| 1 | Very Low |
| 2 | Low |
| 3 | Medium |
| 4 | High |
| 5 | Very High |
