package utils

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestConvertPathVariables(t *testing.T) {
	listOfPaths := []struct {
		Path          string
		ConvertedPath string
	}{
		{Path: "/", ConvertedPath: "/"},
		{Path: "/endpoint-1", ConvertedPath: "/endpoint-1"},
		{Path: "/endpoint-1/:id", ConvertedPath: "/endpoint-1/{id}"},
		{Path: "/endpoint-1/:id/", ConvertedPath: "/endpoint-1/{id}/"},
		{Path: "/endpoint-1/:id1/:id2/:id3", ConvertedPath: "/endpoint-1/{id1}/{id2}/{id3}"},
		{Path: "/endpoint-1/", ConvertedPath: "/endpoint-1/"},
		{Path: "/endpoint-1/:id/upsert", ConvertedPath: "/endpoint-1/{id}/upsert"},
		{Path: "/external-endpoint/:id", ConvertedPath: "/external-endpoint/{id}"},
		{Path: "/:another/external-endpoint", ConvertedPath: "/{another}/external-endpoint"},
	}

	t.Run("convert correctly paths", func(t *testing.T) {
		for _, path := range listOfPaths {
			convertedPath := ConvertPathVariablesToBrackets(path.Path)
			assert.Equal(t, convertedPath, path.ConvertedPath, "Path not converted correctly.")
		}
	})
}

func TestConvertPathVariables2(t *testing.T) {
	listOfPaths := []struct {
		Path          string
		ConvertedPath string
	}{
		{Path: "/", ConvertedPath: "/"},
		{Path: "/endpoint-1", ConvertedPath: "/endpoint-1"},
		{Path: "/endpoint-1/", ConvertedPath: "/endpoint-1/"},
		{Path: "/endpoint-1/{id}", ConvertedPath: "/endpoint-1/:id"},
		{Path: "/endpoint-1/{id}/", ConvertedPath: "/endpoint-1/:id/"},
		{Path: "/endpoint-1/{id1}/{id2}/{id3}", ConvertedPath: "/endpoint-1/:id1/:id2/:id3"},
		{Path: "/endpoint-1/{id}/upsert", ConvertedPath: "/endpoint-1/:id/upsert"},
		{Path: "/:another/external-endpoint", ConvertedPath: "/:another/external-endpoint"},
	}

	t.Run("convert correctly paths", func(t *testing.T) {
		for _, path := range listOfPaths {
			convertedPath := ConvertPathVariablesToColons(path.Path)
			assert.Equal(t, convertedPath, path.ConvertedPath, "Path not converted correctly.")
		}
	})
}
