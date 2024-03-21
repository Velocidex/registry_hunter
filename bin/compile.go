package main

import (
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
)

func doCompile() error {
	rules_compiler := compiler.NewCompiler()

	out_fd, err := os.OpenFile(*output_artifact,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	for _, filename := range *compile_yaml {
		err := rules_compiler.LoadRules(filename)
		if err != nil {
			return err
		}
	}

	artifact, err := rules_compiler.Compile()
	if err != nil {
		return err
	}

	_, err = out_fd.Write([]byte(artifact))
	return err
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
