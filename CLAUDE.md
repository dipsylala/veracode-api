# CLAUDE.md — Guide for LLMs working on veracode-api

## What this project is

A single-binary Go CLI for querying the Veracode platform (SAST, DAST, SCA, application metadata) via the Veracode REST and XML APIs. Read-only by design. No runtime dependencies.

## Build & run

```bash
go build -o veracode-api ./cmd/veracode-api
go build -o veracode-api.exe ./cmd/veracode-api   # Windows

# Run a domain
./veracode-api static --app "Verademo" --violates-policy
./veracode-api apps
```

Requires **Go 1.22+**. There are currently no tests; `go build ./...` is the verification step.

## High-level architecture

```
cmd/veracode-api/        CLI layer — one file per domain command
internal/api/            API client, all Get* methods, output structs
internal/credentials/    Credential loading (YAML file or env vars)
internal/signing/        Veracode HMAC-SHA-256 request signing
internal/workspace/      .veracode-workspace.json resolution
```

The CLI entry point (`main.go`) dispatches by the first argument to a `runXxx(args []string) error` function defined in each domain file.

## The output pipeline (critical to understand)

Every domain follows this pipeline:

```
flag parsing (flag.FlagSet)
    │
    ▼
run(format, app, workspaceRoot, closureFn)
    ├─ bootstrap()   app name → credentials → api.Client → appGUID
    │       └─ closureFn(ctx, client, appGUID, appName) → Renderer
    └─ formatOutput(format, renderer)
       ├─ "json"     → renderer.WriteJSON(stdout)
       └─ "markdown" → renderer.WriteMarkdown(stdout)
```

`apps` is the only domain that bypasses `bootstrap` (it does not need an app GUID).

## The Renderer interface

Every result type must implement:

```go
type Renderer interface {
    WriteJSON(w io.Writer) error
    WriteMarkdown(w io.Writer) error
}
```

Each domain file owns a thin wrapper struct (e.g. `staticOutput`) that embeds the output type from `internal/api` and implements both methods. A compile-time assertion `var _ Renderer = (*fooOutput)(nil)` is placed at the bottom of each domain file. Always include this when adding a new type.

`WriteJSON` always delegates to the shared `writeJSON(w, v)` helper in `run.go`. `WriteMarkdown` is written per-domain.

## Adding a new domain command

1. **`internal/api/client.go`** — define an output struct and a `Get*` method on `*Client`.
2. **`cmd/veracode-api/<domain>.go`** — parse flags, call `run()`, define the wrapper type + `WriteMarkdown`.
3. **`cmd/veracode-api/main.go`** — add a `case "domain":` branch and update the `usage` constant.

See [DEVELOPMENT.md](DEVELOPMENT.md) for a full worked example with copy-paste boilerplate.

## Findings flag sharing

`static`, `dynamic`, and `sca` share a common set of filter flags (severity, CVSS, CWE IDs, `--violates-policy`, `--only-new`, `--all-results`, `--page`, `--size`). These are parsed by `parseFindings` in `findings.go`. Domain-specific flags (e.g. `--sandbox` for static) are registered on the same `flag.FlagSet` *before* calling `parseFindings`.

`apps` has its own `--all-results` flag registered directly in `apps.go`.

## Pagination API design

Paginated resources expose an explicit method pair following the `io.Read` / `io.ReadAll` stdlib pattern:

```go
client.GetFindings(ctx, guid, name, p)        // single page — p.Page and p.Size are honoured
client.GetAllFindings(ctx, guid, name, p)     // all pages — loops fetchFindingsPage internally

client.GetApplications(ctx, page, size)       // single page
client.GetAllApplications(ctx)                // all pages
```

`fetchFindingsPage` is a private method that makes exactly one HTTP call; neither exported method delegates through the other, which avoids infinite-recursion risk.

The CLI layer picks the method via a function variable:

```go
fetch := c.GetFindings
if findings.allResults {
    fetch = c.GetAllFindings
}
out, err := fetch(ctx, appGUID, appName, p)
```

`FindingsParams` has no `AllPages` field — the caller chooses the method instead.

## Authentication

`internal/credentials/credentials.go` loads credentials in this priority order:

1. `~/.veracode/veracode.yml` (`api.key-id`, `api.key-secret`, optional `override-api-base-url`)
2. Env vars: `VERACODE_API_ID`, `VERACODE_API_KEY`, `VERACODE_OVERRIDE_API_BASE_URL`

Base URL is auto-detected: keys starting with `vera01ei-` → `https://api.veracode.eu`; all others → `https://api.veracode.com`.

## HMAC signing

`internal/signing/hmac.go` implements Veracode's HMAC-SHA-256 scheme. It is wired in as an `http.RoundTripper` (`hmacTransport`) in `internal/api/client.go`, so all requests are signed transparently. The client normalises query strings to use `%20` instead of `+` before signing.

## REST vs XML API

Almost everything uses the REST API (`api.veracode.com`). The sole exception is `scaninfo`, which calls `getbuildinfo.do` on the **XML API** (`analysiscenter.veracode.com`). The XML host is derived by replacing `//api.` with `//analysiscenter.` in the configured base URL. The XML types and parser live in `internal/api/buildinfo.go`.

## Sandbox handling

When `--sandbox` is supplied to `static` or `scaninfo`, the value may be either a sandbox name or a sandbox GUID. `client.go` resolves names to GUIDs by calling the sandboxes list endpoint and matching by name. Omitting `--sandbox` uses the latest policy scan context (GUID = `""` sent as the `context` query parameter to the Findings API).

## Known limitations / gotchas

- The `--sandbox` flag is documented as accepting a name, but the Findings API `context` parameter expects a GUID. The resolution logic in `client.go` handles this, but if you are adding code that calls the Findings API directly, make sure you pass the GUID, not the name.
- `include_annot=true` is sent with findings requests by default, but annotation/mitigation data is not fully parsed into the output structs (mitigations are present but sparse).
- `scaninfo` uses the legacy XML API despite the README positioning the CLI as REST-first.

## Key files at a glance

| File | Purpose |
|---|---|
| `cmd/veracode-api/main.go` | CLI dispatch + usage string |
| `cmd/veracode-api/run.go` | `bootstrap`, `run`, `formatOutput`, `Renderer`, helpers |
| `cmd/veracode-api/findings.go` | Shared flag parsing for findings commands |
| `internal/api/client.go` | HTTP client, HMAC transport, all `Get*` methods, core output types |
| `internal/api/buildinfo.go` | XML API types and `GetBuildInfo` method |
| `internal/api/detail.go` | Static/dynamic flaw detail types and `GetStaticFlawDetail` / `GetDynamicFlawDetail` |
| `internal/credentials/credentials.go` | Credential loading |
| `internal/signing/hmac.go` | HMAC-SHA-256 signing |
| `internal/workspace/workspace.go` | `.veracode-workspace.json` resolution |
