package compiler

import (
	"regexp"
	"strings"
)

var (
	_GROUPING_PATTERN = regexp.MustCompile("^(.+)[{]([^{}]+)[}](.*)$")
)

func InString(hay []string, needle string) bool {
	for _, x := range hay {
		if x == needle {
			return true
		}
	}

	return false
}

func _brace_expansion(pattern string, result *[]string) {
	groups := _GROUPING_PATTERN.FindStringSubmatch(pattern)
	if len(groups) > 0 {
		left := groups[1]
		middle := strings.Split(groups[2], ",")
		right := groups[3]

		for _, item := range middle {
			_brace_expansion(left+item+right, result)
		}
	} else if !InString(*result, pattern) {
		*result = append(*result, pattern)
	}
}
