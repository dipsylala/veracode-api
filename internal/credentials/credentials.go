package credentials

// Adapted from github.com/dipsylala/veracode-mcp/credentials/credentials.go

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultBaseURL = "https://api.veracode.com"
	euBaseURL      = "https://api.veracode.eu"
	euKeyPrefix    = "vera01ei-"
)

type veracodeConfig struct {
	API struct {
		KeyID     string `yaml:"key-id"`
		KeySecret string `yaml:"key-secret"`
		BaseURL   string `yaml:"override-api-base-url,omitempty"`
	} `yaml:"api"`
}

// GetCredentials loads Veracode API credentials from ~/.veracode/veracode.yml
// or the environment variables VERACODE_API_ID / VERACODE_API_KEY.
func GetCredentials() (apiID, apiSecret, baseURL string, err error) {
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(homeDir, ".veracode", "veracode.yml")
		apiID, apiSecret, baseURL, err = readCredentialsFile(configPath)
		if err == nil && apiID != "" && apiSecret != "" {
			return apiID, apiSecret, baseURL, nil
		}
	}

	apiID = os.Getenv("VERACODE_API_ID")
	apiSecret = os.Getenv("VERACODE_API_KEY")
	baseURL = os.Getenv("VERACODE_OVERRIDE_API_BASE_URL")
	if baseURL == "" {
		baseURL = detectRegion(apiID)
	}

	if apiID == "" || apiSecret == "" {
		return "", "", "", fmt.Errorf(
			"credentials not found — create ~/.veracode/veracode.yml or set " +
				"VERACODE_API_ID and VERACODE_API_KEY",
		)
	}
	return apiID, apiSecret, baseURL, nil
}

func readCredentialsFile(path string) (string, string, string, error) {
	data, err := os.ReadFile(path) // #nosec G304 — intentional user config read
	if err != nil {
		return "", "", "", err
	}
	var cfg veracodeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", "", "", fmt.Errorf("parse %s: %w", path, err)
	}
	baseURL := cfg.API.BaseURL
	if baseURL == "" {
		baseURL = detectRegion(cfg.API.KeyID)
	}
	return cfg.API.KeyID, cfg.API.KeySecret, baseURL, nil
}

func detectRegion(apiID string) string {
	if strings.HasPrefix(apiID, euKeyPrefix) {
		return euBaseURL
	}
	return defaultBaseURL
}
