package registry_hunter

import (
	"encoding/json"

	"github.com/davecgh/go-spew/spew"
)

func Debug(arg interface{}) {
	spew.Dump(arg)
}

func JsonDump(arg interface{}) string {
	serialized, _ := json.MarshalIndent(arg)
	return string(serialized)
}
