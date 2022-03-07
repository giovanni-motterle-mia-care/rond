package openapi

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func PrepareOASFromFile(t *testing.T, filePath string) *OpenAPISpec {
	t.Helper()

	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	var oas OpenAPISpec
	if err := json.Unmarshal(fileContent, &oas); err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	return &oas
}
