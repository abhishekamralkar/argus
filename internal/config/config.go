package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds values from .argus.yaml. All fields are optional;
// CLI flags override config file values.
type Config struct {
	DB           string `yaml:"db"`
	EmbedModel   string `yaml:"embed_model"`
	LLMModel     string `yaml:"llm_model"`
	MinSeverity  string `yaml:"min_severity"`
	Workers      int    `yaml:"workers"`
	Ecosystems   string `yaml:"ecosystems"`
	ChunkSize    int    `yaml:"chunk_size"`
	ChunkOverlap int    `yaml:"chunk_overlap"`
	TopK         int    `yaml:"top_k"`
	LLMBaseURL   string `yaml:"llm_base_url"`
	EmbedBaseURL string `yaml:"embed_base_url"`
}

var validSeverities = map[string]bool{"": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
var validEcosystems = map[string]bool{"go": true, "python": true, "rust": true, "npm": true}

// Validate checks field bounds and known enum values.
func (c *Config) Validate() error {
	if c.Workers < 0 {
		return fmt.Errorf("workers must be >= 0, got %d", c.Workers)
	}
	if !validSeverities[strings.ToUpper(c.MinSeverity)] {
		return fmt.Errorf("min_severity must be one of LOW, MEDIUM, HIGH, CRITICAL (got %q)", c.MinSeverity)
	}
	if c.Ecosystems != "" {
		for eco := range strings.SplitSeq(c.Ecosystems, ",") {
			eco = strings.TrimSpace(eco)
			if eco != "" && !validEcosystems[eco] {
				return fmt.Errorf("unknown ecosystem %q (valid: go, python, rust)", eco)
			}
		}
	}
	if c.ChunkSize < 0 {
		return fmt.Errorf("chunk_size must be >= 0, got %d", c.ChunkSize)
	}
	if c.ChunkOverlap < 0 {
		return fmt.Errorf("chunk_overlap must be >= 0, got %d", c.ChunkOverlap)
	}
	if c.ChunkSize > 0 && c.ChunkOverlap >= c.ChunkSize {
		return fmt.Errorf("chunk_overlap must be < chunk_size, got %d >= %d", c.ChunkOverlap, c.ChunkSize)
	}
	if c.TopK < 0 {
		return fmt.Errorf("top_k must be >= 0, got %d", c.TopK)
	}
	return nil
}

// Load reads .argus.yaml from the given directory (typically the project root).
// Returns an empty Config if the file does not exist.
func Load(dir string) (*Config, error) {
	path := dir + "/.argus.yaml"
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf(".argus.yaml: %w", err)
	}
	return &cfg, nil
}
