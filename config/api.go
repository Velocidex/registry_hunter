package config

type RuleFile struct {
	Comment  string         `json:"Comment,omitempty"`
	Preamble []string       `json:"Preamble,omitempty"`
	Rules    []RegistryRule `json:"Rules"`
}

type RegistryRule struct {
	Author      string `json:"Author,omitempty"`
	Description string `json:"Description"`
	Category    string `json:"Category"`
	Comment     string `json:"Comment,omitempty"`

	// The query will be running in a remapped environment where
	// certain raw registry hives are mapped into certain paths. For
	// example the SAM file will be mapped into /SAM. Therfore here we
	// only need to present a glob and a root and always use the
	// "registry" accessor.
	Glob string `json:"Glob"`
	Root string `json:"Root"`

	// A possible VQL Query to enrich the data. This receives the row
	// from glob() so has access to anything from the registry key
	// above.
	Details string `json:"Details,omitempty"`

	// A Lambda function that will be used to filter a match. By
	// default we reject Keys (because they have no data).
	// Default filter is x=>NOT IsKey(x=x)
	Filter string `json:"Filter,omitempty"`

	// A registry rule can define VQL to be added to the artifact
	// preamble. This allows the rule to define complex parsers to be
	// used in the Details column.
	Preamble []string `json:"Preamle,omitempty"`
}
