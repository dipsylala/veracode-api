package workspace

// Adapted from github.com/dipsylala/veracode-mcp/workspace/workspace.go

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const workspaceFileName = ".veracode-workspace.json"

type workspaceConfig struct {
	Name string `json:"name"`
}

// ResolveAppName returns the application profile name from the appFlag or the
// workspace config file. If workspaceRoot is empty, the current working
// directory is used.
func ResolveAppName(appFlag, workspaceRoot string) (string, error) {
	if appFlag != "" {
		return appFlag, nil
	}

	dir := workspaceRoot
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve workspace root: %w", err)
	}

	cfgPath := filepath.Join(absDir, workspaceFileName)
	data, err := os.ReadFile(cfgPath) // #nosec G304 — intentional workspace config read
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf(
				"no --app specified and %s not found in %s\n"+
					"Create %s with: {\"name\": \"YourAppProfileName\"}",
				workspaceFileName, absDir, workspaceFileName,
			)
		}
		return "", fmt.Errorf("read %s: %w", workspaceFileName, err)
	}

	var cfg workspaceConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse %s: %w", workspaceFileName, err)
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("%s must contain a non-empty \"name\" field", workspaceFileName)
	}
	return cfg.Name, nil
}
