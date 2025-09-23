package main

import (
	"archive/zip"
	"fmt"
	"os"

	"github.com/Velocidex/registry_hunter/compiler"
	"github.com/alecthomas/kingpin"
)

var (
	compile_cmd  = app.Command("compile", "Build an artifact from a set of Registry Hunter yaml files.")
	compile_yaml = compile_cmd.Arg("input", "Path to the registry hunter yamls files to compile").
			Required().Strings()

	output_artifact = compile_cmd.Flag("output", "Where to write the final artifact").
			Required().String()

	output_meta_artifact = compile_cmd.Flag("meta", "Where to write the meta artifact").String()

	output_make_zip = compile_cmd.Flag("make_zip", "Produce a ZIP file we can use to hunt").
			Bool()

	output_index = compile_cmd.Flag("index", "Where to write the rules index").
			String()
)

func makeZip(rules_compiler *compiler.Compiler) error {
	out_fd, err := os.OpenFile(*output_artifact,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	w := zip.NewWriter(out_fd)
	defer w.Close()

	artifact, err := rules_compiler.Compile()
	if err != nil {
		return err
	}

	f, err := w.Create("Windows.Registry.Hunter.yaml")
	_, err = f.Write([]byte(artifact))
	if err != nil {
		return err
	}

	f, err = w.Create("rules.txt")
	_, err = f.Write([]byte(rules_compiler.GetRules()))
	if err != nil {
		return err
	}

	return err
}

func makeFile(rules_compiler *compiler.Compiler) error {
	out_fd, err := os.OpenFile(*output_artifact,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	artifact, err := rules_compiler.Compile()
	if err != nil {
		return err
	}

	_, err = out_fd.Write([]byte(artifact))
	return err
}

func makeMetaFile(rules_compiler *compiler.Compiler) error {
	out_fd, err := os.OpenFile(*output_meta_artifact,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	artifact, err := rules_compiler.CompileMeta()
	if err != nil {
		return err
	}

	_, err = out_fd.Write([]byte(artifact))
	return err
}

func doCompile() error {
	rules_compiler := compiler.NewCompiler()

	for _, filename := range *compile_yaml {
		err := rules_compiler.LoadRules(filename)
		if err != nil {
			fmt.Printf("Error: Unable to load rules from %v: %v\n",
				filename, err)
			continue
		}
	}

	if *output_index != "" {
		err := rules_compiler.WriteIndex(*output_index)
		if err != nil {
			return err
		}
	}

	if *output_make_zip {
		return makeZip(rules_compiler)
	}

	if *output_meta_artifact != "" {
		err := makeMetaFile(rules_compiler)
		if err != nil {
			return err
		}
	}

	return makeFile(rules_compiler)
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case compile_cmd.FullCommand():
			err := doCompile()
			kingpin.FatalIfError(err, "Compiling artifact")

		default:
			return false
		}
		return true
	})
}
