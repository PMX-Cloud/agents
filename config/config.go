/*
 * Agent Configuration
 *
 * Handles loading and validation of agent configuration from file and environment.
 */

package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	DefaultServerURL = "wss://ws.pmxcloud.cloud/ws/agent"
	DefaultDataDir   = "/var/lib/pmx-cloud"
)

type Config struct {
	Token     string
	ServerURL string
	DataDir   string
}

// Load loads configuration from file and environment variables.
// Environment variables take precedence over file settings.
func Load(path string) (*Config, error) {
	cfg := &Config{
		ServerURL: DefaultServerURL,
		DataDir:   DefaultDataDir,
	}

	// Load from file if it exists
	if _, err := os.Stat(path); err == nil {
		if err := cfg.loadFromFile(path); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	cfg.loadFromEnv()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) loadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "token":
			c.Token = value
		case "server_url":
			c.ServerURL = value
		case "data_dir":
			c.DataDir = value
		}
	}

	return nil
}

func (c *Config) loadFromEnv() {
	if token := os.Getenv("PMX_CLOUD_TOKEN"); token != "" {
		c.Token = token
	}
	if serverURL := os.Getenv("PMX_CLOUD_SERVER_URL"); serverURL != "" {
		c.ServerURL = serverURL
	}
	if dataDir := os.Getenv("PMX_CLOUD_DATA_DIR"); dataDir != "" {
		c.DataDir = dataDir
	}
}

func (c *Config) Validate() error {
	c.Token = strings.TrimSpace(c.Token)
	c.ServerURL = strings.TrimSpace(c.ServerURL)
	c.DataDir = strings.TrimSpace(c.DataDir)

	if c.Token == "" {
		return fmt.Errorf("token is required (set in config file or PMX_CLOUD_TOKEN env var)")
	}

	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	parsedServerURL, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("server_url is invalid: %w", err)
	}
	if parsedServerURL.Scheme != "ws" && parsedServerURL.Scheme != "wss" {
		return fmt.Errorf("server_url must use ws:// or wss://")
	}
	if parsedServerURL.Host == "" {
		return fmt.Errorf("server_url must include a host")
	}

	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}

	return nil
}

func (c *Config) Save(path string) error {
	var sb strings.Builder
	sb.WriteString("# pmx-Cloud Agent Configuration\n")
	sb.WriteString("# This file is managed by the agent. Manual edits may be overwritten.\n")
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("token = %s\n", c.Token))
	sb.WriteString(fmt.Sprintf("server_url = %s\n", c.ServerURL))
	sb.WriteString(fmt.Sprintf("data_dir = %s\n", c.DataDir))

	return os.WriteFile(path, []byte(sb.String()), 0600)
}
