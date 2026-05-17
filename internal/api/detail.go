package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// Raw API response structs
// ---------------------------------------------------------------------------

type staticFlawInfoResponse struct {
	IssueSummary struct {
		AppGUID string `json:"app_guid"`
		Name    string `json:"name"`
		BuildID int    `json:"build_id"`
		IssueID int    `json:"issue_id"`
		Context string `json:"context"`
	} `json:"issue_summary"`
	DataPaths []struct {
		ModuleName   string `json:"module_name"`
		Steps        int    `json:"steps"`
		LocalPath    string `json:"local_path"`
		FunctionName string `json:"function_name"`
		LineNumber   int    `json:"line_number"`
		Calls        []struct {
			DataPath     int    `json:"data_path"`
			FileName     string `json:"file_name"`
			FilePath     string `json:"file_path"`
			FunctionName string `json:"function_name"`
			LineNumber   int    `json:"line_number"`
		} `json:"calls"`
	} `json:"data_paths"`
}

type dynamicFlawInfoResponse struct {
	IssueSummary struct {
		AppGUID        string `json:"app_guid"`
		BuildID        int    `json:"build_id"`
		IssueID        int    `json:"issue_id"`
		CWEID          int    `json:"cwe_id"`
		Description    string `json:"description"`
		Recommendation string `json:"recommendation"`
	} `json:"issue_summary"`
	DynamicFlawInfo struct {
		Request *struct {
			URL           string `json:"url"`
			RawBytes      string `json:"raw_bytes"`
			Method        string `json:"method"`
			Path          string `json:"path"`
			AttackVectors []struct {
				Name        string `json:"name"`
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"attack_vectors"`
		} `json:"request"`
		Response *struct {
			RawBytes string `json:"raw_bytes"`
		} `json:"response"`
	} `json:"dynamic_flaw_info"`
}

// ---------------------------------------------------------------------------
// Output structs
// ---------------------------------------------------------------------------

// StaticDetailOutput is the JSON written to stdout for a static flaw detail.
type StaticDetailOutput struct {
	Success   bool             `json:"success"`
	App       string           `json:"app"`
	Domain    string           `json:"domain"`
	FlawID    int              `json:"flaw_id"`
	DataPaths []DataPathOutput `json:"data_paths"`
}

// DataPathOutput represents one call-stack path from source to sink.
type DataPathOutput struct {
	PathIndex  int          `json:"path_index"`
	Module     string       `json:"module,omitempty"`
	TotalSteps int          `json:"total_steps"`
	Calls      []CallOutput `json:"calls"`
}

// CallOutput is a single frame in a data path.
type CallOutput struct {
	Step         int    `json:"step"`
	Type         string `json:"type"` // source | propagation | sink
	FilePath     string `json:"file_path,omitempty"`
	FileName     string `json:"file_name,omitempty"`
	FunctionName string `json:"function_name,omitempty"`
	LineNumber   int    `json:"line_number,omitempty"`
}

// DynamicDetailOutput is the JSON written to stdout for a dynamic flaw detail.
type DynamicDetailOutput struct {
	Success        bool                 `json:"success"`
	App            string               `json:"app"`
	Domain         string               `json:"domain"`
	FlawID         int                  `json:"flaw_id"`
	CWEID          int                  `json:"cwe_id,omitempty"`
	Description    string               `json:"description,omitempty"`
	Recommendation string               `json:"recommendation,omitempty"`
	URL            string               `json:"url,omitempty"`
	Method         string               `json:"method,omitempty"`
	AttackVectors  []AttackVectorOutput `json:"attack_vectors,omitempty"`
	HTTPRequest    string               `json:"http_request,omitempty"`
	HTTPResponse   string               `json:"http_response,omitempty"`
}

// AttackVectorOutput represents a single attack vector in a dynamic flaw.
type AttackVectorOutput struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

// ---------------------------------------------------------------------------
// Client methods
// ---------------------------------------------------------------------------

// GetStaticFlawDetail fetches the data-path call stack for a SAST finding.
func (c *Client) GetStaticFlawDetail(ctx context.Context, appGUID, appName string, issueID int, sandbox string) (*StaticDetailOutput, error) {
	path := fmt.Sprintf("/appsec/v2/applications/%s/findings/%d/static_flaw_info", appGUID, issueID)
	params := url.Values{}
	if sandbox != "" {
		sandboxGUID, err := c.ResolveSandboxGUID(ctx, appGUID, sandbox)
		if err != nil {
			return nil, err
		}
		params.Set("context", sandboxGUID)
	}

	body, err := c.get(ctx, path, params)
	if err != nil {
		return nil, err
	}

	var raw staticFlawInfoResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse static_flaw_info response: %w", err)
	}

	out := &StaticDetailOutput{
		Success: true,
		App:     appName,
		Domain:  "static",
		FlawID:  issueID,
	}

	for i, dp := range raw.DataPaths {
		dpOut := DataPathOutput{
			PathIndex:  i + 1,
			Module:     dp.ModuleName,
			TotalSteps: len(dp.Calls),
		}
		for j, call := range dp.Calls {
			stepType := "propagation"
			if j == 0 {
				stepType = "source"
			} else if j == len(dp.Calls)-1 {
				stepType = "sink"
			}
			dpOut.Calls = append(dpOut.Calls, CallOutput{
				Step:         j + 1,
				Type:         stepType,
				FilePath:     call.FilePath,
				FileName:     call.FileName,
				FunctionName: call.FunctionName,
				LineNumber:   call.LineNumber,
			})
		}
		out.DataPaths = append(out.DataPaths, dpOut)
	}

	return out, nil
}

// GetDynamicFlawDetail fetches HTTP request/response details for a DAST finding.
func (c *Client) GetDynamicFlawDetail(ctx context.Context, appGUID, appName string, issueID int) (*DynamicDetailOutput, error) {
	path := fmt.Sprintf("/appsec/v2/applications/%s/findings/%d/dynamic_flaw_info", appGUID, issueID)

	body, err := c.get(ctx, path, url.Values{})
	if err != nil {
		return nil, err
	}

	var raw dynamicFlawInfoResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse dynamic_flaw_info response: %w", err)
	}

	out := &DynamicDetailOutput{
		Success:        true,
		App:            appName,
		Domain:         "dynamic",
		FlawID:         issueID,
		CWEID:          raw.IssueSummary.CWEID,
		Description:    raw.IssueSummary.Description,
		Recommendation: raw.IssueSummary.Recommendation,
	}

	if req := raw.DynamicFlawInfo.Request; req != nil {
		out.URL = req.URL
		out.Method = strings.ToUpper(req.Method)
		if req.RawBytes != "" {
			if decoded, err := base64.StdEncoding.DecodeString(req.RawBytes); err == nil {
				out.HTTPRequest = string(decoded)
			}
		}
		for _, av := range req.AttackVectors {
			out.AttackVectors = append(out.AttackVectors, AttackVectorOutput{
				Name:        av.Name,
				Type:        av.Type,
				Description: av.Description,
			})
		}
	}

	if resp := raw.DynamicFlawInfo.Response; resp != nil && resp.RawBytes != "" {
		if decoded, err := base64.StdEncoding.DecodeString(resp.RawBytes); err == nil {
			out.HTTPResponse = string(decoded)
		}
	}

	return out, nil
}
