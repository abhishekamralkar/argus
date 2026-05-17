package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile holds scan parameters for a named configuration preset.
// Zero values mean "not set by this profile"; CLI flags always win.
type Profile struct {
	Workers             int     `yaml:"workers"`
	TopK                int     `yaml:"top_k"`
	SimilarityThreshold float64 `yaml:"min_similarity"`
	LLMModel            string  `yaml:"llm_model"`
	EmbedModel          string  `yaml:"embed_model"`
	MinSeverity         string  `yaml:"min_severity"`
	FailOn              string  `yaml:"fail_on"`
	OutputFormat        string  `yaml:"output"`
}

// builtinProfiles are the profiles available without any .argus.yaml.
var builtinProfiles = map[string]Profile{
	"default": {
		Workers:             4,
		TopK:                10,
		SimilarityThreshold: 0.35,
		FailOn:              "HIGH",
		OutputFormat:        "text",
	},
	"fast": {
		Workers:             8,
		TopK:                5,
		SimilarityThreshold: 0.65,
		MinSeverity:         "HIGH",
		FailOn:              "HIGH",
		OutputFormat:        "text",
	},
	"ci": {
		Workers:             4,
		TopK:                10,
		SimilarityThreshold: 0.55,
		FailOn:              "HIGH",
		OutputFormat:        "sarif",
	},
	"thorough": {
		Workers:             2,
		TopK:                20,
		SimilarityThreshold: 0.40,
		MinSeverity:         "LOW",
		FailOn:              "HIGH",
		OutputFormat:        "text",
	},
}

// Config holds values from .argus.yaml. All fields are optional;
// CLI flags override config file values.
type Config struct {
	DB             string             `yaml:"db"`
	EmbedModel     string             `yaml:"embed_model"`
	LLMModel       string             `yaml:"llm_model"`
	MinSeverity    string             `yaml:"min_severity"`
	Workers        int                `yaml:"workers"`
	Ecosystems     string             `yaml:"ecosystems"`
	ChunkSize      int                `yaml:"chunk_size"`
	ChunkOverlap   int                `yaml:"chunk_overlap"`
	TopK           int                `yaml:"top_k"`
	LLMBaseURL     string             `yaml:"llm_base_url"`
	EmbedBaseURL   string             `yaml:"embed_base_url"`
	DefaultProfile string             `yaml:"default_profile"`
	Profiles       map[string]Profile `yaml:"profiles"`

	// Provider selects the LLM and embedding backend.
	// Valid values: ollama, openai, azure, bedrock, vertex
	// Applies to both LLM and embeddings unless overridden by LLMProvider/EmbedProvider.
	Provider      string `yaml:"provider"`
	LLMProvider   string `yaml:"llm_provider"`   // overrides Provider for LLM
	EmbedProvider string `yaml:"embed_provider"` // overrides Provider for embeddings

	// Azure OpenAI
	AzureEndpoint   string `yaml:"azure_endpoint"`
	AzureAPIVersion string `yaml:"azure_api_version"`

	// AWS Bedrock
	AWSRegion string `yaml:"aws_region"`

	// GCP Vertex AI
	GCPProject  string `yaml:"gcp_project"`
	GCPLocation string `yaml:"gcp_location"`
}

var validSeverities = map[string]bool{"": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
var validEcosystems = map[string]bool{"go": true, "python": true, "rust": true, "npm": true, "maven": true, "nuget": true}
var validOutputFormats = map[string]bool{"": true, "text": true, "json": true, "sarif": true, "cyclonedx": true, "spdx": true}
var validFailOns = map[string]bool{"": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
var validProviders = map[string]bool{"": true, "ollama": true, "openai": true, "azure": true, "bedrock": true, "vertex": true}

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
				return fmt.Errorf("unknown ecosystem %q (valid: go, python, rust, maven, nuget)", eco)
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
	for _, p := range []string{c.Provider, c.LLMProvider, c.EmbedProvider} {
		if !validProviders[strings.ToLower(p)] {
			return fmt.Errorf("provider must be one of ollama, openai, azure, bedrock, vertex (got %q)", p)
		}
	}
	for name, p := range c.Profiles {
		if err := p.validate(); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	return nil
}

func (p *Profile) validate() error {
	if p.Workers < 0 {
		return fmt.Errorf("workers must be >= 0, got %d", p.Workers)
	}
	if p.TopK < 0 {
		return fmt.Errorf("top_k must be >= 0, got %d", p.TopK)
	}
	if p.SimilarityThreshold < 0 || (p.SimilarityThreshold > 1 && p.SimilarityThreshold != 0) {
		return fmt.Errorf("min_similarity must be in [0, 1], got %g", p.SimilarityThreshold)
	}
	if !validSeverities[strings.ToUpper(p.MinSeverity)] {
		return fmt.Errorf("min_severity must be one of LOW, MEDIUM, HIGH, CRITICAL (got %q)", p.MinSeverity)
	}
	if !validFailOns[strings.ToUpper(p.FailOn)] {
		return fmt.Errorf("fail_on must be one of LOW, MEDIUM, HIGH, CRITICAL (got %q)", p.FailOn)
	}
	if !validOutputFormats[strings.ToLower(p.OutputFormat)] {
		return fmt.Errorf("output must be one of text, json, sarif, cyclonedx, spdx (got %q)", p.OutputFormat)
	}
	return nil
}

// ResolveLLMProvider returns the effective provider for LLM calls.
// LLMProvider takes precedence over the shared Provider field.
func (c *Config) ResolveLLMProvider() string {
	if c == nil {
		return ""
	}
	if c.LLMProvider != "" {
		return strings.ToLower(c.LLMProvider)
	}
	return strings.ToLower(c.Provider)
}

// ResolveEmbedProvider returns the effective provider for embedding calls.
// EmbedProvider takes precedence over the shared Provider field.
func (c *Config) ResolveEmbedProvider() string {
	if c == nil {
		return ""
	}
	if c.EmbedProvider != "" {
		return strings.ToLower(c.EmbedProvider)
	}
	return strings.ToLower(c.Provider)
}

// ResolveProfile looks up a profile by name. User-defined profiles in the
// config file take precedence over built-ins. Returns (nil, false) when the
// name is not found in either set.
func (c *Config) ResolveProfile(name string) (*Profile, bool) {
	if name == "" {
		return nil, false
	}
	if c != nil && c.Profiles != nil {
		if p, ok := c.Profiles[name]; ok {
			return &p, true
		}
	}
	if p, ok := builtinProfiles[name]; ok {
		return &p, true
	}
	return nil, false
}

// AllProfileNames returns a sorted list of all profile names (built-ins first,
// then user-defined extras).
func (c *Config) AllProfileNames() []string {
	seen := make(map[string]bool)
	var names []string
	for n := range builtinProfiles {
		seen[n] = true
		names = append(names, n)
	}
	if c != nil {
		for n := range c.Profiles {
			if !seen[n] {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

// BuiltinProfiles returns a copy of the built-in profile map for display.
func BuiltinProfiles() map[string]Profile {
	out := make(map[string]Profile, len(builtinProfiles))
	for k, v := range builtinProfiles {
		out[k] = v
	}
	return out
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
