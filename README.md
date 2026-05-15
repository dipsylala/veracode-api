# veracode-api

A single-binary CLI for querying Veracode platform findings (SAST, DAST, SCA) via the REST API. No runtime dependencies — just build and run.

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

## Usage

```
veracode-api <domain> [flags]
```

### Domains

| Domain      | Description |
|-------------|-------------|
| `static`    | SAST findings from the latest policy scan |
| `dynamic`   | DAST findings from the latest policy scan |
| `sca`       | SCA component vulnerability findings |
| `scaninfo`  | Scan/build metadata for an application |

### Common flags (all domains)

| Flag | Default | Description |
|------|---------|-------------|
| `--app string` | | Application profile name |
| `--workspace-root dir` | cwd | Directory containing `.veracode-workspace.json` |
| `--severity int` | | Exact severity filter (0 = informational … 5 = very high) |
| `--status string` | | Comma-separated statuses: `NEW`, `OPEN`, `FIXED`, `MITIGATED` |
| `--cwe-ids string` | | Comma-separated CWE IDs |
| `--violates-policy` | false | Only policy-violating findings |
| `--page int` | 0 | Page number |
| `--size int` | 100 | Page size |

### Static flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sandbox string` | | Sandbox name (omit for policy scan) |
| `--exclude-mitigations` | false | Exclude mitigation annotation details |
| `--flaw-id string` | | Return call-stack data paths for a specific finding |

### Dynamic flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sandbox string` | | Sandbox name |
| `--exclude-mitigations` | false | Exclude mitigation annotation details |
| `--flaw-id string` | | Return HTTP request/response details for a specific finding |

### SCA flags

| Flag | Default | Description |
|------|---------|-------------|
| `--severity-gte int` | | Minimum severity (inclusive) |
| `--cvss-gte float` | | Minimum CVSS score (inclusive) |
| `--only-exploitable` | false | Only exploitable vulnerabilities |
| `--only-new` | false | Only new findings |

### Scan Info flags

| Flag | Default | Description |
|------|---------|-------------|
| `--build-id int` | 0 | Specific build/scan ID (0 = latest scan) |

## Examples

```bash
# All high/very-high SAST findings that violate policy
veracode-api static --app "MyApp" --severity-gte 4 --violates-policy

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

# Latest scan metadata
veracode-api scaninfo --app "MyApp"

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
  "total_findings": 42,
  "page": 0,
  "page_size": 100,
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
|-------|-------|
| 0 | Informational |
| 1 | Very Low |
| 2 | Low |
| 3 | Medium |
| 4 | High |
| 5 | Very High |
