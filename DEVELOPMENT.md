# Developer Guide

## Architecture overview

```
cmd/veracode-api/
  main.go          — CLI entry point; dispatches to runXxx() per domain
  run.go           — bootstrap(), run(), formatOutput(), Renderer interface
  findings.go      — shared flag parsing (parseFindings) for static/dynamic/sca
  static.go        — runStatic()
  dynamic.go       — runDynamic()
  sca.go           — runSCA()
  appinfo.go       — runAppInfo()
  sandboxes.go     — runSandboxes()
  scaninfo.go      — runScanInfo()
  apps.go          — runApps()

internal/api/
  client.go        — API client, all Get* methods, FindingsParams, output types
  buildinfo.go     — XML-based scan/build info types and parser
  detail.go        — static/dynamic flaw detail types and parser
```

## Output pipeline

Every domain command follows the same pipeline:

```
flag parsing
    │
    ▼
run(format, app, workspaceRoot, closureFn)
    │
    ├─ bootstrap()          resolve app name → credentials → client → appGUID
    │       │
    │       └─ closureFn(ctx, client, appGUID, appName)
    │               │
    │               └─ returns a Renderer wrapper (e.g. &staticOutput{out})
    │
    └─ formatOutput(format, result)
       ├─ "json"     → result.WriteJSON(stdout)
       └─ "markdown" → result.WriteMarkdown(stdout)
```

`apps` and `apps`-like commands that do not resolve an app GUID call
`formatOutput` directly after their own bootstrap.

## The Renderer interface

Every value returned from a closure must implement `Renderer`:

```go
type Renderer interface {
    WriteJSON(w io.Writer) error
    WriteMarkdown(w io.Writer) error
}
```

Each command file owns its wrapper type and `WriteMarkdown`/`WriteJSON` implementations.
All current domains implement both JSON and markdown rendering.

## Adding a new domain command

1. **Add the API method** in `internal/api/client.go`:
   - Define your output type (e.g. `WidgetOutput`).
   - Implement `func (c *Client) GetWidgets(...) (*WidgetOutput, error)`.

2. **Create `cmd/veracode-api/widgets.go`**:
   ```go
   func runWidgets(args []string) error {
       fs := flag.NewFlagSet("widgets", flag.ContinueOnError)
       fs.SetOutput(os.Stderr)
       var appFlag, workspaceRoot, format string
       fs.StringVar(&appFlag, "app", "", "Application profile name")
       fs.StringVar(&workspaceRoot, "workspace-root", "", "...")
       fs.StringVar(&format, "format", "json", "Output format: json or markdown")
       // domain-specific flags here

       if err := fs.Parse(args); err != nil {
           fmt.Fprintf(os.Stderr, "veracode-api widgets: %v\n", err)
           printFlagDefaults(fs)
           return err
       }
       return run(format, appFlag, workspaceRoot, func(ctx context.Context, c *api.Client, appGUID, appName string) (Renderer, error) {
           out, err := c.GetWidgets(ctx, appGUID, appName)
           if err != nil {
               return nil, err
           }
           return &widgetsOutput{out}, nil
       })
   }
   ```

3. **Add the wrapper type** to `widgets.go` with `WriteMarkdown` and a
   compile-time assertion:
   ```go
   type widgetsOutput struct{ *api.WidgetOutput }

   func (w *widgetsOutput) WriteJSON(ww io.Writer) error { return writeJSON(ww, w) }

   func (w *widgetsOutput) WriteMarkdown(ww io.Writer) error {
       fmt.Fprintf(ww, "# Widgets\n\n")
       // Render fields from w.WidgetOutput.
       return nil
   }

   var _ Renderer = (*widgetsOutput)(nil)
   ```
   The `var _` line costs nothing at runtime but causes an immediate build
   failure if `WriteMarkdown` is ever removed or has the wrong signature.

4. **Register the command** in `main.go`:
   ```go
   case "widgets":
       err = runWidgets(os.Args[2:])
   ```
   Update the `usage` constant to document the new flags.

## Maintaining markdown for an existing domain

Each domain's markdown renderer lives next to its command implementation.

1. **Open the domain's command file** and find its `WriteMarkdown` method, e.g.:
   ```go
   func (a *appinfoOutput) WriteMarkdown(w io.Writer) error {
       fmt.Fprintf(w, "# %s\n\n", a.Name)
       // ... render fields from a.ApplicationDetailOutput
       return nil
   }
   ```

2. Keep table-oriented output stable where possible. Users may paste markdown
   into reports, so prefer adding columns deliberately instead of reshaping every
   renderer during unrelated changes.

3. The `w io.Writer` parameter means the implementation is testable — you can
   pass a `bytes.Buffer` in tests.

## Findings commands (static / dynamic / sca)

These share flag parsing via `parseFindings` in `findings.go`. Domain-specific
flags (e.g. `--sandbox`, `--only-exploitable`) are registered on the flagset
before calling `parseFindings`.

Each command's `run*` function wraps the result in its own output type
(e.g. `staticOutput`, `dynamicOutput`, `scaOutput`) and calls `run()` directly.
Markdown rendering is implemented in `WriteMarkdown` on each type, in its
own file — `static.go`, `dynamic.go`, `sca.go`.

## API endpoints in use

### REST API (`api.veracode.com`)

| Endpoint | Method | Used by |
| --- | --- | --- |
| `/appsec/v1/applications` | GET | `GetAppInfo` (name lookup), `GetApplications` / `GetAllApplications` |
| `/appsec/v1/applications/{guid}` | GET | `GetApplicationDetails` |
| `/appsec/v1/applications/{guid}/sandboxes` | GET | `GetSandboxes` / `GetAllSandboxes` |
| `/appsec/v2/applications/{guid}/findings` | GET | `GetFindings` / `GetAllFindings` |
| `/appsec/v2/applications/{guid}/findings/{issue_id}/static_flaw_info` | GET | `GetStaticFlawDetail` |
| `/appsec/v2/applications/{guid}/findings/{issue_id}/dynamic_flaw_info` | GET | `GetDynamicFlawDetail` |

### XML API (`analysiscenter.veracode.com`)

| Endpoint | Method | Used by |
| --- | --- | --- |
| `/api/5.0/getbuildinfo.do` | GET | `GetBuildInfo` (`scaninfo` domain) |

The XML host is derived at runtime by replacing `//api.` with `//analysiscenter.` in the configured base URL.
