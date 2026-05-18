package parser

// Dependency represents a single resolved dependency.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string // "go", "python", "rust", "npm"
	Direct    bool   // true = declared in the project manifest (not a transitive dep)
}
