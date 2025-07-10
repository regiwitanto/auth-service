package config

import "testing"

func TestLoadConfig(t *testing.T) {
	// Simple test to ensure config can load
	_, err := LoadConfig()
	if err != nil {
		t.Errorf("Failed to load config: %v", err)
	}
}

func TestNewTestConfig(t *testing.T) {
	// Simple test to ensure test config can load
	_, err := NewTestConfig()
	if err != nil {
		t.Errorf("Failed to load test config: %v", err)
	}
}
