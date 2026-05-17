package api

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
)

// ---------------------------------------------------------------------------
// XML response structs  (getbuildinfo.do)
// ---------------------------------------------------------------------------

type xmlBuildInfo struct {
	XMLName xml.Name `xml:"buildinfo"`
	AppID   int      `xml:"app_id,attr"`
	BuildID int      `xml:"build_id,attr"`
	Build   xmlBuild `xml:"build"`
}

type xmlBuild struct {
	Version                string            `xml:"version,attr"`
	BuildID                int               `xml:"build_id,attr"`
	Submitter              string            `xml:"submitter,attr"`
	Platform               string            `xml:"platform,attr"`
	LifecycleStage         string            `xml:"lifecycle_stage,attr"`
	ResultsReady           bool              `xml:"results_ready,attr"`
	PolicyName             string            `xml:"policy_name,attr"`
	PolicyComplianceStatus string            `xml:"policy_compliance_status,attr"`
	PolicyUpdatedDate      string            `xml:"policy_updated_date,attr"`
	RulesStatus            string            `xml:"rules_status,attr"`
	GracePeriodExpired     bool              `xml:"grace_period_expired,attr"`
	ScanOverdue            bool              `xml:"scan_overdue,attr"`
	AnalysisUnits          []xmlAnalysisUnit `xml:"analysis_unit"`
}

type xmlAnalysisUnit struct {
	AnalysisType  string `xml:"analysis_type,attr"`
	Status        string `xml:"status,attr"`
	EngineVersion string `xml:"engine_version,attr"`
	ScanType      string `xml:"scan_type,attr"`
}

// xmlAPIError is returned by the XML API on failure.
type xmlAPIError struct {
	XMLName xml.Name `xml:"error"`
	Message string   `xml:",chardata"`
}

// ---------------------------------------------------------------------------
// Output structs
// ---------------------------------------------------------------------------

// BuildInfoOutput is the JSON written to stdout for a scaninfo query.
type BuildInfoOutput struct {
	Success                bool                 `json:"success"`
	App                    string               `json:"app"`
	AppID                  int                  `json:"app_id"`
	BuildID                int                  `json:"build_id"`
	ScanName               string               `json:"scan_name"`
	Submitter              string               `json:"submitter,omitempty"`
	Platform               string               `json:"platform,omitempty"`
	LifecycleStage         string               `json:"lifecycle_stage,omitempty"`
	ResultsReady           bool                 `json:"results_ready"`
	PolicyName             string               `json:"policy_name,omitempty"`
	PolicyComplianceStatus string               `json:"policy_compliance_status,omitempty"`
	PolicyUpdatedDate      string               `json:"policy_updated_date,omitempty"`
	RulesStatus            string               `json:"rules_status,omitempty"`
	GracePeriodExpired     bool                 `json:"grace_period_expired"`
	ScanOverdue            bool                 `json:"scan_overdue"`
	AnalysisUnits          []AnalysisUnitOutput `json:"analysis_units,omitempty"`
}

// AnalysisUnitOutput is a single scan engine entry within a build.
type AnalysisUnitOutput struct {
	AnalysisType  string `json:"analysis_type"`
	Status        string `json:"status"`
	EngineVersion string `json:"engine_version,omitempty"`
	ScanType      string `json:"scan_type,omitempty"`
}

// ---------------------------------------------------------------------------
// Client method
// ---------------------------------------------------------------------------

// GetBuildInfo fetches scan/build metadata via the Veracode XML API (v5).
// Pass buildID = 0 to retrieve the latest scan for the application.
func (c *Client) GetBuildInfo(ctx context.Context, appName string, appID, buildID, sandboxID int) (*BuildInfoOutput, error) {
	params := url.Values{}
	params.Set("app_id", strconv.Itoa(appID))
	if buildID != 0 {
		params.Set("build_id", strconv.Itoa(buildID))
	}
	if sandboxID != 0 {
		params.Set("sandbox_id", strconv.Itoa(sandboxID))
	}

	body, err := c.getXML(ctx, "/api/5.0/getbuildinfo.do", params)
	if err != nil {
		return nil, err
	}

	// Check for an API-level error response before attempting full parse.
	var apiErr xmlAPIError
	if xmlErr := xml.Unmarshal(body, &apiErr); xmlErr == nil && apiErr.Message != "" {
		return nil, fmt.Errorf("veracode API error: %s", apiErr.Message)
	}

	var raw xmlBuildInfo
	if err := xml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse buildinfo response: %w", err)
	}

	units := make([]AnalysisUnitOutput, 0, len(raw.Build.AnalysisUnits))
	for _, u := range raw.Build.AnalysisUnits {
		units = append(units, AnalysisUnitOutput{
			AnalysisType:  u.AnalysisType,
			Status:        u.Status,
			EngineVersion: u.EngineVersion,
			ScanType:      u.ScanType,
		})
	}

	return &BuildInfoOutput{
		Success:                true,
		App:                    appName,
		AppID:                  raw.AppID,
		BuildID:                raw.BuildID,
		ScanName:               raw.Build.Version,
		Submitter:              raw.Build.Submitter,
		Platform:               raw.Build.Platform,
		LifecycleStage:         raw.Build.LifecycleStage,
		ResultsReady:           raw.Build.ResultsReady,
		PolicyName:             raw.Build.PolicyName,
		PolicyComplianceStatus: raw.Build.PolicyComplianceStatus,
		PolicyUpdatedDate:      raw.Build.PolicyUpdatedDate,
		RulesStatus:            raw.Build.RulesStatus,
		GracePeriodExpired:     raw.Build.GracePeriodExpired,
		ScanOverdue:            raw.Build.ScanOverdue,
		AnalysisUnits:          units,
	}, nil
}
