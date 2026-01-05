package compiler

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Velocidex/registry_hunter/converters"
	"github.com/Velocidex/yaml/v2"
)

type Mapping struct {
	RECmdRules map[string]string `json:"RECmdRules"`
}

func VerifyRECmd(
	reb_directory string, rules []string,
	mapping_file string) error {

	fd, err := os.Open(mapping_file)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return err
	}

	mapping := &Mapping{}
	err = yaml.UnmarshalStrict(data, mapping)
	if err != nil {
		return err
	}

	files, err := os.ReadDir(reb_directory)
	if err != nil {
		return err
	}

	rules_converter := converters.NewConverter()
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".reb") {
			continue
		}

		fd, err := os.Open(filepath.Join(reb_directory, file.Name()))
		if err != nil {
			return err
		}
		defer fd.Close()

		data, err := ioutil.ReadAll(fd)
		if err != nil {
			return err
		}
		fd.Close()

		err = rules_converter.ParseYaml(string(data), "")
		if err != nil {
			return err
		}
	}

	rules_compiler := NewCompiler()
	for _, filename := range rules {
		err = rules_compiler.LoadRules(filename)
		if err != nil {
			return err
		}
	}

	counter := 0

	// Iterate over all the the REB rules
	for _, rule := range rules_converter.GetRules() {
		// If the description is the same as an existing rule, this is
		// fine.
		_, pres := rules_compiler.md[rule.Description]
		if pres {
			continue
		}

		_, pres = mapping.RECmdRules[rule.Description]
		if pres {
			continue
		}

		serialized, err := yaml.Marshal(rule)
		if err != nil {
			continue
		}

		fmt.Printf("%v\n", string(serialized))
		counter++
	}

	fmt.Printf("Total %v rules are not implemented\n", counter)

	return nil
}
