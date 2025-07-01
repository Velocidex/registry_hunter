package compiler

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/registry_hunter/config"
	"github.com/Velocidex/yaml/v2"

	_ "embed"
)

var (
	// The following roots refer to the virtual hives that are mounted
	// on the remap config. Rules may not specific different roots
	// from these.
	allowedRoots = []string{
		// Rules that do not glob can have an empty root glob.
		"",
		"/",
		"Amcache",
		"HKEY_USERS",
		"SAM",
		"HKEY_LOCAL_MACHINE\\Security",
		"HKEY_LOCAL_MACHINE\\System",
		"HKEY_LOCAL_MACHINE\\Software",
	}
)

//go:embed template.yaml
var artifact_template string

type templateParameters struct {
	Name     string
	Metadata string
	Rules    []config.RegistryRule
	Preamble string

	// Rules that are full queries
	QueriesJSON string

	Categories     []string
	CategoriesJSON string

	Time string
}

type Compiler struct {
	rules []config.RegistryRule
	md    map[string]config.RegistryRule

	// Detect rules using the same globs - these are not supported and
	// one of the rules will be rejected
	globs map[string]config.RegistryRule

	PreambleVerses []string

	categories map[string]bool

	queries []config.RegistryRule
}

func NewCompiler() *Compiler {
	return &Compiler{
		md:         make(map[string]config.RegistryRule),
		globs:      make(map[string]config.RegistryRule),
		categories: make(map[string]bool),
	}
}

func (self *Compiler) serialize(item interface{}) string {
	serialized, err := json.Marshal(item)
	if err != nil {
		return ""
	}
	return string(serialized)
}

var (
	pathSepRegex = regexp.MustCompile(`[/\\]+`)
)

func (self *Compiler) normalizeRoot(description, root string) string {
	for _, allowed := range allowedRoots {
		if strings.EqualFold(allowed, root) {
			return allowed
		}
	}

	fmt.Printf("Warning: Rule %v uses an unsupported Root: %v\n",
		description, root)
	return root
}

// FIXME: Currentl we duplicate the rules because each rule can only
// have one glob but it would be ideal if the same rule could have
// multiple globs.
func (self *Compiler) normalizeRule(r *config.RegistryRule) []config.RegistryRule {
	r.Glob = strings.TrimPrefix(pathSepRegex.ReplaceAllString(r.Glob, "\\"), "\\")
	r.Root = self.normalizeRoot(r.Description,
		pathSepRegex.ReplaceAllString(r.Root, "\\"))

	// Expand the glob expression to support brace expansions
	globs := []string{}
	_brace_expansion(r.Glob, &globs)

	res := []config.RegistryRule{}
	for _, glob := range globs {
		rule_copy := *r
		rule_copy.Glob = glob
		res = append(res, rule_copy)
	}
	return res
}

func (self *Compiler) LoadRules(filename string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return err
	}

	rules := &config.RuleFile{}
	err = yaml.UnmarshalStrict(data, rules)
	if err != nil {
		return err
	}

	fmt.Printf("Loading %v rules from %v\n", len(rules.Rules), filename)

	// Add preables from rules
	for _, r := range rules.Rules {
		for _, r := range self.normalizeRule(&r) {

			if r.Query != "" {
				self.queries = append(self.queries, r)
				continue
			}

			key := r.Root + r.Glob
			existing_rule, pres := self.globs[key]
			if pres {
				fmt.Printf("Rule %v by %v has the same glob (%v) as rule %v by %v... skipping this rule!\n",
					r.Description, r.Author, r.Glob,
					existing_rule.Description, existing_rule.Author)
			}
			self.globs[key] = r

			if len(r.Preamble) > 0 {
				self.PreambleVerses = append(self.PreambleVerses, r.Preamble...)
			}
			self.categories[r.Category] = true
			self.rules = append(self.rules, r)
		}
	}

	// Add global preambles
	self.PreambleVerses = append(self.PreambleVerses, rules.Preamble...)
	return nil
}

func (self *Compiler) buildMetadata() string {
	serialized, _ := json.Marshal(self.rules)

	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write(serialized)
	gz.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (self *Compiler) compress(in string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write([]byte(in))
	gz.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (self *Compiler) buildPreamble() string {
	preamble := ordereddict.NewDict()

	for _, p := range self.PreambleVerses {
		if p == "" {
			continue
		}

		_, exists := preamble.Get(p)
		if !exists {
			preamble.Set(p, true)
		}
	}

	result := ""
	for _, k := range preamble.Keys() {
		result += k + "\n"
	}

	return self.indent(result, "    ")
}

func (self *Compiler) indent(in string, indent string) string {
	lines := strings.Split(in, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		result = append(result, indent+l)
	}

	return strings.Join(result, "\n")
}

func (self *Compiler) saveFile(filename string, item interface{}) error {
	out_fd, err := os.OpenFile(filename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	serialized, err := yaml.Marshal(item)
	if err != nil {
		return err
	}

	_, err = out_fd.Write(serialized)
	return err
}

func (self *Compiler) buildCategories() (result []string) {
	for k := range self.categories {
		result = append(result, k)
	}

	sort.Strings(result)
	return result
}

func (self *Compiler) GetRules() []byte {
	serialized, _ := yaml.Marshal(self.rules)
	return serialized
}

func (self *Compiler) Compile() (string, error) {
	tmpl, err := template.New("").Parse(artifact_template)
	if err != nil {
		return "", err
	}

	categories := self.buildCategories()
	parameters := &templateParameters{
		Name:           "Windows.Registry.Hunter",
		Metadata:       self.buildMetadata(),
		Rules:          self.rules,
		Preamble:       self.buildPreamble(),
		Categories:     categories,
		CategoriesJSON: self.serialize(categories),
		QueriesJSON:    self.compress(self.serialize(self.queries)),
		Time:           time.Now().UTC().Format(time.RFC3339),
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, parameters)
	return string(b.Bytes()), err
}
