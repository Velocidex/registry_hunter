package compiler

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
)

func calculateTemplate(template_str string, params interface{}) (string, error) {
	var templ *template.Template
	var err error

	funcMap := template.FuncMap{
		"Indent":   indentTemplate,
		"ReadFile": readFile,

		// Compress a template into base64
		"Compress": func(name string, args interface{}) string {
			b := &bytes.Buffer{}
			err := templ.ExecuteTemplate(b, name, args)
			if err != nil {
				return fmt.Sprintf("<%v>", err)
			}

			// Compress the string and encode as base64
			bc := &bytes.Buffer{}
			gz, err := gzip.NewWriterLevel(bc, 9)
			if err != nil {
				return fmt.Sprintf("<%v>", err)
			}

			gz.Write(b.Bytes())
			gz.Close()

			enc := &bytes.Buffer{}
			encoder := base64.NewEncoder(base64.StdEncoding, enc)
			encoder.Write(bc.Bytes())
			encoder.Close()
			return string(enc.Bytes())
		},
	}

	templ, err = template.New("").
		Funcs(sprig.TxtFuncMap()).
		Funcs(funcMap).Parse(template_str)
	if err != nil {
		return "", err
	}

	b := &bytes.Buffer{}
	err = templ.Execute(b, params)
	if err != nil {
		return "", err
	}

	return string(b.Bytes()), nil
}

func indentTemplate(args ...interface{}) interface{} {
	if len(args) != 2 {
		return ""
	}

	template, ok := args[0].(string)
	if !ok {
		return ""
	}

	indent_size, ok := args[1].(int)
	if !ok {
		return template
	}

	return indent(template, indent_size)
}

func indent(in string, indent int) string {
	indent_str := strings.Repeat(" ", indent)
	lines := strings.Split(in, "\n")
	result := []string{}
	for _, l := range lines {
		result = append(result, indent_str+l)
	}
	return strings.Join(result, "\n")
}

func readFile(args ...interface{}) interface{} {
	result := ""

	for _, arg := range args {
		path, ok := arg.(string)
		if !ok {
			continue
		}

		fd, err := os.Open(path)
		if err != nil {
			continue
		}
		defer fd.Close()

		data, err := ioutil.ReadAll(fd)
		if err != nil {
			continue
		}

		result += string(data)
	}

	return result
}
