package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/v3/assert"
)

func TestFetchOpenAPI(t *testing.T) {
	t.Run("fetches json OAS", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		url := "http://localhost:3000/documentation/json"

		openApiSpec, err := fetchOpenAPI(url)

		assert.Assert(t, gock.IsDone(), "Mock has not been invoked")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "very.very.composed.permission",
					},
				},
			},
			"/no-permission": PathVerbs{
				"get":  VerbConfig{},
				"post": VerbConfig{},
			},
		})
	})

	t.Run("request execution fails for invalid URL", func(t *testing.T) {
		url := "http://invalidUrl.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for invalid URL syntax", func(t *testing.T) {
		url := "	http://url with a tab.com"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for unexpected server response", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(500).
			JSON(map[string]string{"error": "InternalServerError"})

		url := "http://localhost:3000/documentation/json"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})

	t.Run("request execution fails for unexpected server response", func(t *testing.T) {
		defer gock.Off()

		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200)

		url := "http://localhost:3000/documentation/json"

		_, err := fetchOpenAPI(url)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, errors.Is(err, ErrRequestFailed), "unexpected error")
	})
}

func TestLoadOASFile(t *testing.T) {
	t.Run("get oas config from file", func(t *testing.T) {
		openAPIFile, err := loadOASFile("./mocks/pathsConfig.json")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openAPIFile != nil, "unexpected nil result")
		assert.DeepEqual(t, openAPIFile.Paths, OpenAPIPaths{
			"/users-from-static-file/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/no-permission-from-static-file": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("fail for invalid filePath", func(t *testing.T) {
		_, err := loadOASFile("./notExistingFilePath.json")

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, err != nil, "failed documentation file read")
	})
}

func TestLoadOAS(t *testing.T) {
	log, _ := test.NewNullLogger()

	t.Run("if TargetServiceOASPath & APIPermissionsFilePath are set together, expect to read oas from static file", func(t *testing.T) {
		envs := EnvironmentVariables{
			TargetServiceHost:      "localhost:3000",
			TargetServiceOASPath:   "/documentation/json",
			APIPermissionsFilePath: "./mocks/pathsConfig.json",
		}
		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users-from-static-file/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/no-permission-from-static-file": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("expect to fetch oasApiSpec from API", func(t *testing.T) {
		envs := EnvironmentVariables{
			TargetServiceHost:    "localhost:3000",
			TargetServiceOASPath: "/documentation/json",
		}

		defer gock.Off()
		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, gock.IsDone(), "Mock has not been invoked")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "foobar",
					},
				},
				"post": VerbConfig{
					Permission: XPermission{
						AllowPermission: "notexistingpermission",
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					Permission: XPermission{
						AllowPermission: "very.very.composed.permission",
					},
				},
			},
			"/no-permission": PathVerbs{
				"post": VerbConfig{},
				"get":  VerbConfig{},
			},
		})
	})

	t.Run("expect to throw if TargetServiceOASPath or APIPermissionsFilePath is not set", func(t *testing.T) {
		envs := EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		}
		_, err := loadOAS(log, envs)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, err != nil, fmt.Errorf("missing environment variables one of %s or %s is required", TargetServiceOASPathEnvKey, APIPermissionsFilePathEnvKey))
	})
}

func TestFindPermission(t *testing.T) {
	log, _ := test.NewNullLogger()
	oas := prepareOASFromFile(t, "./mocks/nestedPathsConfig.json")
	openApiSpec, _ := loadOAS(log, envs)
	OASRouter := openApiSpec.PrepareOASRouter(oas)

	found, err := openApiSpec.FindPermission(OASRouter, "/not/existing/route", "GET")
	assert.Equal(t, XPermission{}, found)
	assert.Equal(t, err.Error(), "not found oas permission: GET /not/existing/route")

	found, err = openApiSpec.FindPermission(OASRouter, "/no/method", "PUT")
	assert.Equal(t, XPermission{}, found)
	assert.Equal(t, err.Error(), "not found oas permission: PUT /no/method")

	found, err = openApiSpec.FindPermission(OASRouter, "use/method/that/not/existing/put", "PUT")
	assert.Equal(t, XPermission{}, found)
	assert.Equal(t, err.Error(), "not found oas permission: PUT use/method/that/not/existing/put")

	found, err = openApiSpec.FindPermission(OASRouter, "/foo/bar/barId", "GET")
	assert.Equal(t, XPermission{AllowPermission: "foo_bar_params"}, found)
	assert.Equal(t, err, nil)

	found, err = openApiSpec.FindPermission(OASRouter, "/foo/bar/barId/another-params-not-configured", "GET")
	assert.Equal(t, XPermission{AllowPermission: "foo_bar"}, found)
	assert.Equal(t, err, nil)

	found, err = openApiSpec.FindPermission(OASRouter, "/foo/bar/nested/case/really/nested", "GET")
	assert.Equal(t, XPermission{AllowPermission: "foo_bar_nested_case"}, found)
	assert.Equal(t, err, nil)

	found, err = openApiSpec.FindPermission(OASRouter, "/foo/bar/nested", "GET")
	assert.Equal(t, XPermission{AllowPermission: "foo_bar_nested"}, found)
	assert.Equal(t, err, nil)

	found, err = openApiSpec.FindPermission(OASRouter, "/foo/simble", "PATCH")
	assert.Equal(t, XPermission{AllowPermission: "foo"}, found)
	assert.Equal(t, err, nil)
}
