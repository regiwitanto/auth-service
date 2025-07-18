package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Skip this test in CI environments since it requires env files
	if os.Getenv("CI") != "" || os.Getenv("SKIP_TESTS") != "" {
		t.Skip("Skipping LoadConfig test which requires env files")
	}

	// Simple test to ensure config can load
	_, err := LoadConfig()
	if err != nil {
		t.Errorf("Failed to load config: %v", err)
	}
}

func TestLoadTestConfig(t *testing.T) {
	// Skip this test in CI environments since it requires env files
	if os.Getenv("CI") != "" || os.Getenv("SKIP_TESTS") != "" {
		t.Skip("Skipping LoadTestConfig test which requires env files")
	}

	// Simple test to ensure test config can load
	cfg, err := LoadTestConfig()
	if err != nil {
		t.Errorf("Failed to create test config: %v", err)
	}

	if cfg.JWT.Secret == "" {
		t.Error("Test config should have a JWT secret")
	}

	if cfg.Database.DBName == "" {
		t.Error("Test config should have a database name")
	}
}
