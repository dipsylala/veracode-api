package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"veracode-api/internal/signing"
)

// Client makes authenticated requests to the Veracode REST API.
type Client struct {
	http    *http.Client
	baseURL string
}

// hmacTransport injects the HMAC Authorization header on every request.
type hmacTransport struct {
	apiID, apiKey string
}

func (t *hmacTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request: RoundTrip must not modify the original.
	r2 := req.Clone(req.Context())
	// Veracode HMAC signing requires %20 for spaces, not +
	if r2.URL.RawQuery != "" {
		r2.URL.RawQuery = strings.ReplaceAll(r2.URL.RawQuery, "+", "%20")
	}
	auth, err := signing.CalculateAuthorizationHeader(r2.URL, r2.Method, t.apiID, t.apiKey)
	if err != nil {
		return nil, fmt.Errorf("HMAC auth: %w", err)
	}
	r2.Header.Set("Authorization", auth)
	return http.DefaultTransport.RoundTrip(r2)
}

// NewClient creates an authenticated Veracode API client.
func NewClient(apiID, apiKey, baseURL string) *Client {
	return &Client{
		http: &http.Client{
			Transport: &hmacTransport{apiID: apiID, apiKey: apiKey},
			Timeout:   30 * time.Second,
		},
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

func (c *Client) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed (401) — check credentials in ~/.veracode/veracode.yml")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found (404) — check the application name")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *Client) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	rawURL := c.baseURL + path
	if len(params) > 0 {
		rawURL += "?" + params.Encode()
	}
	return c.fetch(ctx, rawURL)
}

// getXML calls the Veracode XML API (analysiscenter.veracode.com) instead of
// the REST API (api.veracode.com), deriving the host from the configured base URL.
func (c *Client) getXML(ctx context.Context, path string, params url.Values) ([]byte, error) {
	base := strings.Replace(c.baseURL, "//api.", "//analysiscenter.", 1)
	rawURL := base + path
	if len(params) > 0 {
		rawURL += "?" + params.Encode()
	}
	return c.fetch(ctx, rawURL)
}

// ---------------------------------------------------------------------------
// Application lookup
// ---------------------------------------------------------------------------

type appSearchResponse struct {
	Embedded struct {
		Applications []struct {
			GUID    string `json:"guid"`
			ID      int    `json:"id"`
			Profile struct {
				Name string `json:"name"`
			} `json:"profile"`
		} `json:"applications"`
	} `json:"_embedded"`
	Page struct {
		TotalElements int `json:"total_elements"`
		Number        int `json:"number"`
		Size          int `json:"size"`
	} `json:"page"`
}

// AppInfo holds the identifiers for a Veracode application.
type AppInfo struct {
	GUID string // REST API UUID
	ID   int    // Legacy numeric ID (used by the XML API)
	Name string
}

// ApplicationSummary is one application profile in the apps command output.
type ApplicationSummary struct {
	GUID string `json:"guid"`
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ApplicationListOutput is the JSON written to stdout for an apps query.
type ApplicationListOutput struct {
	Success           bool                 `json:"success"`
	TotalApplications int                  `json:"total_applications"`
	Page              int                  `json:"page"`
	Size              int                  `json:"size"`
	Applications      []ApplicationSummary `json:"applications"`
}

// ApplicationDetailOutput is the JSON written to stdout for an appinfo query.
type ApplicationDetailOutput struct {
	Success     bool           `json:"success"`
	App         string         `json:"app"`
	GUID        string         `json:"guid"`
	ID          int            `json:"id"`
	Name        string         `json:"name"`
	Application map[string]any `json:"application"`
}

// SandboxInfo holds the identifiers for a Veracode sandbox.
type SandboxInfo struct {
	GUID string `json:"guid"`
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// SandboxListOutput is the JSON written to stdout for a sandbox query.
type SandboxListOutput struct {
	Success        bool          `json:"success"`
	App            string        `json:"app"`
	TotalSandboxes int           `json:"total_sandboxes"`
	Sandboxes      []SandboxInfo `json:"sandboxes"`
}

type sandboxListResponse struct {
	Embedded struct {
		Sandboxes []struct {
			GUID        string `json:"guid"`
			ID          int    `json:"id"`
			Name        string `json:"name"`
			SandboxName string `json:"sandbox_name"`
			Profile     struct {
				Name string `json:"name"`
			} `json:"profile"`
		} `json:"sandboxes"`
	} `json:"_embedded"`
}

// GetAppInfo resolves an application name to its GUID and numeric ID.
func (c *Client) GetAppInfo(ctx context.Context, name string) (AppInfo, error) {
	body, err := c.get(ctx, "/appsec/v1/applications", url.Values{
		"name": {name},
		"size": {"500"},
	})
	if err != nil {
		return AppInfo{}, fmt.Errorf("application lookup: %w", err)
	}
	var resp appSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return AppInfo{}, fmt.Errorf("parse application response: %w", err)
	}
	apps := resp.Embedded.Applications
	if len(apps) == 0 {
		return AppInfo{}, fmt.Errorf("application not found: %s", name)
	}
	available := make([]string, 0, len(apps))
	for _, a := range apps {
		appName := strings.TrimSpace(a.Profile.Name)
		if appName != "" {
			available = append(available, appName)
		}
		if strings.EqualFold(appName, strings.TrimSpace(name)) {
			return AppInfo{GUID: a.GUID, ID: a.ID, Name: appName}, nil
		}
	}
	if len(available) > 0 {
		return AppInfo{}, fmt.Errorf("application not found with exact name %q (matched: %s)", name, strings.Join(available, ", "))
	}
	return AppInfo{}, fmt.Errorf("application not found with exact name %q", name)
}

// GetAppGUID resolves an application name to its GUID.
func (c *Client) GetAppGUID(ctx context.Context, name string) (string, error) {
	info, err := c.GetAppInfo(ctx, name)
	if err != nil {
		return "", err
	}
	return info.GUID, nil
}

// GetApplications returns a page of visible application profiles.
func (c *Client) GetApplications(ctx context.Context, page, size int) (*ApplicationListOutput, error) {
	params := url.Values{}
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("size", fmt.Sprintf("%d", size))

	body, err := c.get(ctx, "/appsec/v1/applications", params)
	if err != nil {
		return nil, fmt.Errorf("application list: %w", err)
	}

	var resp appSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse application list response: %w", err)
	}

	applications := make([]ApplicationSummary, 0, len(resp.Embedded.Applications))
	for _, app := range resp.Embedded.Applications {
		applications = append(applications, ApplicationSummary{
			GUID: app.GUID,
			ID:   app.ID,
			Name: app.Profile.Name,
		})
	}

	return &ApplicationListOutput{
		Success:           true,
		TotalApplications: resp.Page.TotalElements,
		Page:              resp.Page.Number,
		Size:              resp.Page.Size,
		Applications:      applications,
	}, nil
}

// GetApplicationDetails returns the full application profile details for an app.
func (c *Client) GetApplicationDetails(ctx context.Context, appGUID, appName string) (*ApplicationDetailOutput, error) {
	body, err := c.get(ctx, fmt.Sprintf("/appsec/v1/applications/%s", appGUID), nil)
	if err != nil {
		return nil, fmt.Errorf("application details: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse application details response: %w", err)
	}
	delete(raw, "_links")

	var summary struct {
		GUID    string `json:"guid"`
		ID      int    `json:"id"`
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(body, &summary); err != nil {
		return nil, fmt.Errorf("parse application details summary: %w", err)
	}

	name := summary.Profile.Name
	if name == "" {
		name = appName
	}

	return &ApplicationDetailOutput{
		Success:     true,
		App:         appName,
		GUID:        summary.GUID,
		ID:          summary.ID,
		Name:        name,
		Application: raw,
	}, nil
}

// GetSandboxes returns the sandboxes for an application profile.
func (c *Client) GetSandboxes(ctx context.Context, appGUID string) ([]SandboxInfo, error) {
	body, err := c.get(ctx, fmt.Sprintf("/appsec/v1/applications/%s/sandboxes", appGUID), nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox lookup: %w", err)
	}

	var resp sandboxListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse sandbox response: %w", err)
	}

	sandboxes := make([]SandboxInfo, 0, len(resp.Embedded.Sandboxes))
	for _, sandbox := range resp.Embedded.Sandboxes {
		name := sandbox.Name
		if name == "" {
			name = sandbox.SandboxName
		}
		if name == "" {
			name = sandbox.Profile.Name
		}

		sandboxes = append(sandboxes, SandboxInfo{
			GUID: sandbox.GUID,
			ID:   sandbox.ID,
			Name: name,
		})
	}

	return sandboxes, nil
}

// ResolveSandboxGUID accepts either a sandbox GUID or a sandbox name.
func (c *Client) ResolveSandboxGUID(ctx context.Context, appGUID, sandbox string) (string, error) {
	info, err := c.ResolveSandboxInfo(ctx, appGUID, sandbox)
	if err != nil {
		return "", err
	}
	return info.GUID, nil
}

// ResolveSandboxInfo accepts either a sandbox GUID or a sandbox name.
func (c *Client) ResolveSandboxInfo(ctx context.Context, appGUID, sandbox string) (SandboxInfo, error) {
	if sandbox == "" {
		return SandboxInfo{}, nil
	}

	sandboxes, err := c.GetSandboxes(ctx, appGUID)
	if err != nil {
		return SandboxInfo{}, err
	}

	for _, candidate := range sandboxes {
		if strings.EqualFold(candidate.GUID, sandbox) || strings.EqualFold(candidate.Name, sandbox) {
			return candidate, nil
		}
	}

	available := make([]string, 0, len(sandboxes))
	for _, candidate := range sandboxes {
		if candidate.Name != "" {
			available = append(available, candidate.Name)
		}
	}

	if len(available) == 0 {
		return SandboxInfo{}, fmt.Errorf("sandbox not found: %s", sandbox)
	}

	return SandboxInfo{}, fmt.Errorf("sandbox not found: %s (available: %s)", sandbox, strings.Join(available, ", "))
}

// GetSandboxList returns the sandbox list in CLI output format.
func (c *Client) GetSandboxList(ctx context.Context, appGUID, appName string) (*SandboxListOutput, error) {
	sandboxes, err := c.GetSandboxes(ctx, appGUID)
	if err != nil {
		return nil, err
	}

	return &SandboxListOutput{
		Success:        true,
		App:            appName,
		TotalSandboxes: len(sandboxes),
		Sandboxes:      sandboxes,
	}, nil
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// FindingsParams holds all supported filter parameters.
type FindingsParams struct {
	ScanType           string
	Severity           *int
	SeverityGte        *int
	CvssGte            *float64
	Status             []string
	CWEIDs             []string
	ViolatesPolicy     *bool
	Sandbox            string
	IncludeMitigations bool
	OnlyExploitable    bool
	OnlyNew            bool
	Page               int
	Size               int
}

// raw API response types — only fields we surface in output

type rawFindingsPage struct {
	Embedded struct {
		Findings []rawFinding `json:"findings"`
	} `json:"_embedded"`
	Page struct {
		TotalElements int64 `json:"total_elements"`
		Number        int   `json:"number"`
		Size          int   `json:"size"`
	} `json:"page"`
}

type rawFinding struct {
	IssueID        int    `json:"issue_id"`
	ScanType       string `json:"scan_type"`
	Description    string `json:"description"`
	BuildID        int    `json:"build_id"`
	ViolatesPolicy bool   `json:"violates_policy"`
	FindingStatus  struct {
		Status         string `json:"status"`
		Resolution     string `json:"resolution"`
		FirstFoundDate string `json:"first_found_date"`
		LastSeenDate   string `json:"last_seen_date"`
		New            bool   `json:"new"`
	} `json:"finding_status"`
	FindingDetails struct {
		Severity int `json:"severity"`
		CWE      struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"cwe"`
		// SAST
		FilePath       string `json:"file_path"`
		FileName       string `json:"file_name"`
		FileLineNumber int    `json:"file_line_number"`
		Module         string `json:"module"`
		Title          string `json:"title"`
		Exploitability int    `json:"exploitability"`
		AttackVector   string `json:"attack_vector"`
		// DAST
		URL string `json:"url"`
		// SCA
		ComponentFilename string  `json:"component_filename"`
		Version           string  `json:"version"`
		CVEID             string  `json:"cve_id"`
		CVSS              float64 `json:"cvss"`
	} `json:"finding_details"`
}

// OutputFinding is the clean per-finding structure written to stdout.
type OutputFinding struct {
	IssueID        int     `json:"issue_id,omitempty"`
	ScanType       string  `json:"scan_type"`
	Severity       int     `json:"severity"`
	CWEID          int     `json:"cwe_id,omitempty"`
	CWEName        string  `json:"cwe_name,omitempty"`
	Status         string  `json:"status"`
	Resolution     string  `json:"resolution,omitempty"`
	ViolatesPolicy bool    `json:"violates_policy"`
	IsNew          bool    `json:"new,omitempty"`
	FirstFoundDate string  `json:"first_found_date,omitempty"`
	LastSeenDate   string  `json:"last_seen_date,omitempty"`
	Description    string  `json:"description,omitempty"`
	Title          string  `json:"title,omitempty"`
	FilePath       string  `json:"file_path,omitempty"`
	FileName       string  `json:"file_name,omitempty"`
	LineNumber     int     `json:"line_number,omitempty"`
	Module         string  `json:"module,omitempty"`
	Exploitability int     `json:"exploitability,omitempty"`
	AttackVector   string  `json:"attack_vector,omitempty"`
	URL            string  `json:"url,omitempty"`
	Component      string  `json:"component,omitempty"`
	Version        string  `json:"version,omitempty"`
	CVE            string  `json:"cve,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
}

// Output is the JSON envelope written to stdout.
type Output struct {
	Success    bool            `json:"success"`
	App        string          `json:"app"`
	Domain     string          `json:"domain"`
	BuildID    int             `json:"build_id,omitempty"`
	TotalCount int64           `json:"total_count"`
	Page       int             `json:"page"`
	Size       int             `json:"size"`
	Findings   []OutputFinding `json:"findings"`
}

// GetFindings fetches findings for an application and returns structured output.
func (c *Client) GetFindings(ctx context.Context, appGUID, appName string, p FindingsParams) (*Output, error) {
	params := url.Values{}
	params.Set("scan_type", p.ScanType)
	params.Set("page", fmt.Sprintf("%d", p.Page))
	params.Set("size", fmt.Sprintf("%d", p.Size))

	if p.Severity != nil {
		params.Set("severity", fmt.Sprintf("%d", *p.Severity))
	}
	if p.SeverityGte != nil {
		params.Set("severity_gte", fmt.Sprintf("%d", *p.SeverityGte))
	}
	if p.CvssGte != nil {
		params.Set("cvss_gte", fmt.Sprintf("%.1f", *p.CvssGte))
	}
	if len(p.Status) > 0 {
		for _, s := range p.Status {
			params.Add("finding_status", strings.TrimSpace(s))
		}
	}
	if len(p.CWEIDs) > 0 {
		params.Set("cwe", strings.Join(p.CWEIDs, ","))
	}
	if p.ViolatesPolicy != nil {
		params.Set("violates_policy", fmt.Sprintf("%t", *p.ViolatesPolicy))
	}
	if p.Sandbox != "" {
		sandboxGUID, err := c.ResolveSandboxGUID(ctx, appGUID, p.Sandbox)
		if err != nil {
			return nil, err
		}
		params.Set("context", sandboxGUID)
	}
	if p.IncludeMitigations {
		params.Set("include_annot", "true")
	}
	if p.OnlyNew {
		params.Set("new", "true")
	}
	if p.OnlyExploitable {
		params.Set("sca_dep_mode", "DIRECT")
	}

	path := fmt.Sprintf("/appsec/v2/applications/%s/findings", appGUID)
	body, err := c.get(ctx, path, params)
	if err != nil {
		return nil, err
	}

	var page rawFindingsPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("parse findings response: %w", err)
	}

	// build_id is the same for all findings in a scan — extract from the first.
	var buildID int
	if len(page.Embedded.Findings) > 0 {
		buildID = page.Embedded.Findings[0].BuildID
	}

	findings := make([]OutputFinding, 0, len(page.Embedded.Findings))
	for _, f := range page.Embedded.Findings {
		d := f.FindingDetails
		out := OutputFinding{
			IssueID:        f.IssueID,
			ScanType:       f.ScanType,
			Severity:       d.Severity,
			CWEID:          d.CWE.ID,
			CWEName:        d.CWE.Name,
			Status:         f.FindingStatus.Status,
			Resolution:     f.FindingStatus.Resolution,
			ViolatesPolicy: f.ViolatesPolicy,
			IsNew:          f.FindingStatus.New,
			FirstFoundDate: f.FindingStatus.FirstFoundDate,
			LastSeenDate:   f.FindingStatus.LastSeenDate,
			Description:    f.Description,
			Title:          d.Title,
			FilePath:       d.FilePath,
			FileName:       d.FileName,
			LineNumber:     d.FileLineNumber,
			Module:         d.Module,
			Exploitability: d.Exploitability,
			AttackVector:   d.AttackVector,
			URL:            d.URL,
			Component:      d.ComponentFilename,
			Version:        d.Version,
			CVE:            d.CVEID,
			CVSS:           d.CVSS,
		}
		findings = append(findings, out)
	}

	return &Output{
		Success:    true,
		App:        appName,
		Domain:     strings.ToLower(p.ScanType),
		BuildID:    buildID,
		TotalCount: page.Page.TotalElements,
		Page:       page.Page.Number,
		Size:       page.Page.Size,
		Findings:   findings,
	}, nil
}
