package utils

import "regexp"

var matchColons = regexp.MustCompile(`\/:(\w+)`)

func ConvertPathVariablesToBrackets(path string) string {
	return matchColons.ReplaceAllString(path, "/{$1}")
}

var matchBrackets = regexp.MustCompile(`\/{(\w+)}`)

func ConvertPathVariablesToColons(path string) string {
	return matchBrackets.ReplaceAllString(path, "/:$1")
}
