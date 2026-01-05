package main

import (
	"github.com/Velocidex/registry_hunter/compiler"
	"github.com/alecthomas/kingpin"
)

var (
	verify_cmd       = app.Command("verify", "Verify rules.")
	verify_recmd_cmd = verify_cmd.Command("recmd", "Verify RECmd rules")
	recmd_reb_files  = verify_recmd_cmd.Flag(
		"recmddir", "Path to the RECmd .reb files").Required().String()

	rules_files = verify_recmd_cmd.Arg(
		"rulesdir", "Path to the Velociraptor rules files").
		Required().Strings()

	mapping_file = verify_recmd_cmd.Flag(
		"mapping", "The Mapping file to use").
		Required().String()
)

func doVerify() error {
	return compiler.VerifyRECmd(*recmd_reb_files, *rules_files, *mapping_file)
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case verify_recmd_cmd.FullCommand():
			err := doVerify()
			kingpin.FatalIfError(err, "Verify RECmd")

		default:
			return false
		}
		return true
	})
}
