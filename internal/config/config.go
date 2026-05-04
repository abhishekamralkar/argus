package config

import (
	"os"

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
	return &cfg, nil
}
