package converters

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Velocidex/registry_hunter/config"
	"github.com/Velocidex/yaml/v2"
)

// Description of fields are documented in !RECmdBatch.guide
type KeyDescription struct {
	Description string `json:"Description"`
	HiveType    string `json:"HiveType"`
	Category    string `json:"Category"`

	// This value should match the KeyPath of the data within the
	// Windows Registry that you want RECmd to parse
	KeyPath string `json:"KeyPath"`

	// This value coincides with the ValueName found at the KeyPath
	// listed above. By specifying this ValueName, you only want the
	// date stored under this specific ValueName to display in the
	// RECmd CSV output
	ValueName string `json:"ValueName"`

	// Recursion on the KeyPath specificed will not occur since this
	// is marked false. That means RECmd will not look for data stored
	// within the ValueName specified beyond the KeyPath address
	// specified
	Recursive bool `json:"Recursive"`

	// RECmd can handle basic timestamp conversions, including but not
	// limited to Windows Filetime. The particular value stored under
	// the specified ValueName at the KeyPath address specified above
	// happens to be stored in binary as Windows Filetime, therefore,
	// setting FILETIME as our value for BinaryConvert will make this
	// a human readable timestamp within the RECmd CSV output
	BinaryConvert string `json:"BinaryConvert"`
	Comment       string `json:"Comment"`
	Disabled      bool   `json:"Disabled"`
}

type RECmdBatch struct {
	Description string           `json:"Description"`
	Author      string           `json:"Author"`
	Keys        []KeyDescription `json:"Keys"`
	Disabled    bool             `json:"Disabled"`
}

type RuleError struct {
	Description string
	Error       string
}

type RECmdConverter struct {
	batch_files []*RECmdBatch
	errors      []RuleError

	output config.RuleFile
}

func (self *RECmdConverter) GetRules() []config.RegistryRule {
	return self.output.Rules
}

func (self *RECmdConverter) Dump() string {
	serialized, _ := yaml.Marshal(self.output)
	return string(serialized)
}

func NewConverter() *RECmdConverter {
	return &RECmdConverter{}
}

func (self *RECmdConverter) rejectRule(description, reason string) {
	self.errors = append(self.errors, RuleError{
		Description: description,
		Error:       reason,
	})
}

func (self *RECmdConverter) Errors() []RuleError {
	return self.errors
}

func (self *RECmdConverter) ParseYaml(data string) error {
	batch_file := &RECmdBatch{}
	err := yaml.Unmarshal([]byte(data), batch_file)
	if err != nil {
		return err
	}

	if batch_file.Disabled {
		return nil
	}

	self.batch_files = append(self.batch_files, batch_file)

	for _, key := range batch_file.Keys {
		if key.Disabled {
			continue
		}

		rule := config.RegistryRule{
			Author:      batch_file.Author,
			Description: key.Description,
			Comment:     key.Comment,
			Category:    key.Category,
		}

		err := mapHive(key.HiveType, &rule)
		if err != nil {
			self.rejectRule(key.Description,
				fmt.Sprintf("While processing %v: %v", key.Description, err))
			continue
		}

		rule.Glob += filterKeyPath(key.KeyPath)

		// Recursive means that we recurse into the key
		if key.Recursive {
			rule.Glob += "\\**"
		}

		// This is not always specified
		if key.ValueName != "" {
			rule.Glob += "\\" + escapeQuotes(filterValue(key.ValueName))
		}

		rule.Glob = strings.TrimPrefix(rule.Glob, "\\")

		if key.BinaryConvert != "" {
			err := validateBinaryConvert(key.BinaryConvert, &rule)
			if err != nil {
				self.rejectRule(key.Description,
					fmt.Sprintf("While processing %v: %v",
						key.Description, err))
				continue
			}
		}

		self.output.Rules = append(self.output.Rules, rule)
	}

	return nil
}

func escapeQuotes(in string) string {
	if strings.Contains(in, "\"") {
		return "\"" + strings.Replace(in, "\"", "\\\"", -1) + "\""
	}
	return in
}

func validateBinaryConvert(name string, rule *config.RegistryRule) error {
	switch strings.ToUpper(name) {
	case "EPOCH":
		rule.Details = "Epoch(value=Data.Value)"

	case "FILETIME":
		rule.Details = "Filetime(value=Data.Value)"

	case "IP":
		rule.Details = "FormatIP(value=Data.Value)"

	default:
		return errors.New("Unknown binary convertion " + name)
	}
	return nil
}

// Map the hive into the remapped registry space. This needs to
// correspond with the remapping created via the compiler's remapping
// strategies.
func mapHive(name string, rule *config.RegistryRule) error {

	switch strings.ToUpper(name) {
	case "USERS":
		rule.Root = "HKEY_USERS"

	case "NTUSER":
		// Rely on mapping C:\Users\*\NTUSER.Dat
		rule.Root = "HKEY_USERS"
		rule.Glob = "*\\"

	case "SYSTEM":
		// Rely on mapping C:\Windows\System32\config\SYSTEM
		rule.Root = "HKEY_LOCAL_MACHINE\\System"

	case "SECURITY":
		// Rely on mapping C:\Windows\System32\config\SECURITY
		rule.Root = "HKEY_LOCAL_MACHINE\\Security"

	case "SOFTWARE":
		// Rely on mapping C:\Windows\System32\config\SOFTWARE
		rule.Root = "HKEY_LOCAL_MACHINE\\Software"

	case "SAM":
		// Rely on mapping C:\Windows\System32\config\SAM
		rule.Root = "SAM"

	case "USRCLASS":
		// Rely on mapping C:\Users\*\UserClass.Dat
		rule.Root = "HKEY_USERS"
		rule.Glob = "*\\Software\\Classes"

		// The BCD hive file is usually located in the boot partition
		// so we can not remap the raw map. We need to rely on the API
		// to remap it.
	case "BCD":
		rule.Root = "HKEY_LOCAL_MACHINE\\BCD00000000"

	case "AMCACHE":
		rule.Root = "Amcache"

	default:
		return fmt.Errorf("Unknown hive '%v'", name)
	}

	return nil
}

var (
	default_regex = regexp.MustCompile("(?i)\\(default\\)")
	brace_regex   = regexp.MustCompile("[{}]")
)

func filterKeyPath(in string) string {
	in = default_regex.ReplaceAllString(in, "")
	in = brace_regex.ReplaceAllString(in, "?")
	return in
}

func filterValue(in string) string {
	in = default_regex.ReplaceAllString(in, "@")
	in = brace_regex.ReplaceAllString(in, "?")
	return in
}
