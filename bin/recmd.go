package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/Velocidex/registry_hunter/converters"
	"github.com/alecthomas/kingpin"
)

var (
	convert_cmd = app.Command("convert", "Convert from RECmd batch files to Registry Hunter specifications.")

	batch = convert_cmd.Arg("batch", "Path to the batch file to compile").
		Required().Strings()

	output = convert_cmd.Flag("output", "Where to write the converted rules").
		Required().String()
)

func doConvert() error {
	rules_converter := converters.NewConverter()

	out_fd, err := os.OpenFile(*output,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	// Sort the files to maintain stable order.
	batch_files := *batch
	sort.Strings(batch_files)

	for _, filename := range batch_files {
		fd, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer fd.Close()

		data, err := ioutil.ReadAll(fd)
		if err != nil {
			return err
		}

		err = rules_converter.ParseYaml(string(data))
		if err != nil {
			return err
		}
	}

	_, err = out_fd.Write([]byte(rules_converter.Dump()))
	if err != nil {
		return err
	}

	for _, err := range rules_converter.Errors() {
		fmt.Printf("Rule Rejected: %v: %v\n", err.Description, err.Error)
	}

	return nil
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case convert_cmd.FullCommand():
			err := doConvert()
			kingpin.FatalIfError(err, "Compiling artifact")

		default:
			return false
		}
		return true
	})
}
