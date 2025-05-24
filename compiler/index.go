package compiler

import (
	"encoding/json"
	"os"
)

func (self *Compiler) WriteIndex(path string) error {
	out_fd, err := os.OpenFile(path,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	serialized, _ := json.Marshal(self.rules)
	out_fd.Write(serialized)
	return out_fd.Close()
}
