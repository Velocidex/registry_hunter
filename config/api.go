package config

type RuleFile struct {
	Rules []RegistryRule `json:"Rules"`
}

type RegistryRule struct {
	Author      string `json:"Author"`
	Description string `json:"Description,omitempty"`
	Category    string `json:"Category,omitempty"`
	Comment     string `json:"Comment,omitempty"`

	// The query will be running in a remapped environment where
	// certain raw registry hives are mapped into certain paths. For
	// example the SAM file will be mapped into /SAM. Therfore here we
	// only need to present a glob and a root and always use the
	// "registry" accessor.
	Glob string `json:"Glob,omitempty"`
	Root string `json:"Root,omitempty"`

	// A possible VQL Query to enrich the data. This receives the row
	// from glob() so has access to anything from the registry key
	// above.
	Details string `json:"Details,omitempty"`

	// A registry rule can define VQL to be added to the artifact
	// preamble. This allows the rule to define complex parsers to be
	// used in the Details column.
	Preamle string `json:"Preamle,omitempty"`
}
