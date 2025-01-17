// Copyright 2021 Mia srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rond-authz/rond/internal/config"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
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
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "todo"},
					},
				},
				"head": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "todo"},
					},
				},
				"post": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "notexistingpermission"},
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "very.very.composed.permission"},
					},
				},
			},
			"/no-permission": PathVerbs{
				"get":  VerbConfig{},
				"post": VerbConfig{},
			},
			"/eval/composed/permission/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "very.very.composed.permission.with.eval"},
					},
				},
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
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{
							PolicyName:    "foobar",
							GenerateQuery: true,
							QueryOptions:  QueryOptions{HeaderName: "customHeaderKey"},
						},
					},
				},
				"post": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{
							PolicyName: "notexistingpermission",
						},
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
		envs := config.EnvironmentVariables{
			TargetServiceHost:      "localhost:3000",
			TargetServiceOASPath:   "/documentation/json",
			APIPermissionsFilePath: "./mocks/pathsConfig.json",
		}
		openApiSpec, err := loadOASFromFileOrNetwork(log, envs)
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users-from-static-file/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{
							PolicyName:    "foobar",
							GenerateQuery: true,
							QueryOptions:  QueryOptions{HeaderName: "customHeaderKey"},
						},
					},
				},
				"post": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{
							PolicyName: "notexistingpermission",
						},
					},
				},
			},
			"/no-permission-from-static-file": PathVerbs{
				"post": VerbConfig{},
			},
		})
	})

	t.Run("expect to fetch oasApiSpec from API", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceHost:    "localhost:3000",
			TargetServiceOASPath: "/documentation/json",
		}

		defer gock.Off()
		gock.New("http://localhost:3000").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		openApiSpec, err := loadOASFromFileOrNetwork(log, envs)
		assert.Assert(t, gock.IsDone(), "Mock has not been invoked")
		assert.Assert(t, err == nil, "unexpected error")
		assert.Assert(t, openApiSpec != nil, "unexpected nil result")
		assert.DeepEqual(t, openApiSpec.Paths, OpenAPIPaths{
			"/users/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "todo"},
					},
				},
				"head": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "todo"},
					},
				},
				"post": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "notexistingpermission"},
					},
				},
			},
			"/composed/permission/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "very.very.composed.permission"},
					},
				},
			},
			"/no-permission": PathVerbs{
				"post": VerbConfig{},
				"get":  VerbConfig{},
			},
			"/eval/composed/permission/": PathVerbs{
				"get": VerbConfig{
					PermissionV2: &RondConfig{
						RequestFlow: RequestFlow{PolicyName: "very.very.composed.permission.with.eval"},
					},
				},
			},
		})
	})

	t.Run("expect to throw if TargetServiceOASPath or APIPermissionsFilePath is not set", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		}
		_, err := loadOASFromFileOrNetwork(log, envs)

		t.Logf("Expected error occurred: %s", err.Error())
		assert.Assert(t, err != nil, fmt.Errorf("missing environment variables one of %s or %s is required", config.TargetServiceOASPathEnvKey, config.APIPermissionsFilePathEnvKey))
	})
}

func TestFindPermission(t *testing.T) {
	t.Run("nested cases", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/nestedPathsConfig.json")
		OASRouter := oas.PrepareOASRouter()

		found, err := oas.FindPermission(OASRouter, "/not/existing/route", "GET")
		assert.Equal(t, RondConfig{}, found)
		assert.Equal(t, err.Error(), fmt.Sprintf("%s: GET /not/existing/route", ErrNotFoundOASDefinition))

		found, err = oas.FindPermission(OASRouter, "/no/method", "PUT")
		assert.Equal(t, RondConfig{}, found)
		assert.Equal(t, err.Error(), fmt.Sprintf("%s: PUT /no/method", ErrNotFoundOASDefinition))

		found, err = oas.FindPermission(OASRouter, "/use/method/that/not/existing/put", "PUT")
		assert.Equal(t, RondConfig{}, found)
		assert.Equal(t, err.Error(), fmt.Sprintf("%s: PUT /use/method/that/not/existing/put", ErrNotFoundOASDefinition))

		found, err = oas.FindPermission(OASRouter, "/foo/bar/barId", "GET")
		assert.Equal(t, RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "foo_bar_params",
				GenerateQuery: true,
				QueryOptions: QueryOptions{
					HeaderName: "customHeaderKey",
				},
			},
		}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/barId/another-params-not-configured", "GET")
		assert.Equal(t, RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "foo_bar",
				GenerateQuery: true,
				QueryOptions: QueryOptions{
					HeaderName: "customHeaderKey",
				},
			},
		}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/nested/case/really/nested", "GET")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "foo_bar_nested_case"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/bar/nested", "GET")
		assert.Equal(t, RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "foo_bar_nested",
				GenerateQuery: true,
				QueryOptions: QueryOptions{
					HeaderName: "customHeaderKey",
				},
			},
		}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/foo/simble", "PATCH")
		assert.Equal(t, RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "foo",
				GenerateQuery: true,
				QueryOptions: QueryOptions{
					HeaderName: "customHeaderKey",
				},
			},
		}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all", "GET")
		assert.Equal(t, RondConfig{}, found)
		assert.Equal(t, err.Error(), fmt.Sprintf("%s: GET /test/all", ErrNotFoundOASDefinition))

		found, err = oas.FindPermission(OASRouter, "/test/all/", "GET")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_get"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "GET")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_get"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "POST")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_post"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "PUT")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_all"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "PATCH")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_all"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "DELETE")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_all"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/test/all/verb", "HEAD")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "permission_for_all"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/projects/", "POST")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "project_all"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/projects/", "GET")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "project_get"}}, found)
		assert.Equal(t, err, nil)
	})

	t.Run("encoded cases", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/mockForEncodedTest.json")
		OASRouter := oas.PrepareOASRouter()

		found, err := oas.FindPermission(OASRouter, "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%252Fcms-backend%252FcmsProperties.json", "POST")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "allow_commit"}}, found)
		assert.Equal(t, err, nil)

		found, err = oas.FindPermission(OASRouter, "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%2Fcms-backend%2FcmsProperties.json", "POST")
		assert.Equal(t, RondConfig{RequestFlow: RequestFlow{PolicyName: "allow_commit"}}, found)
		assert.Equal(t, err, nil)
	})
}

func TestGetXPermission(t *testing.T) {
	t.Run(`GetXPermission fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetXPermission(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetXPermission returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), XPermissionKey{}, &RondConfig{RequestFlow: RequestFlow{PolicyName: "foo"}})
		permission, err := GetXPermission(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, permission != nil, "XPermission not found.")
	})
}

func TestGetPolicyEvaluators(t *testing.T) {
	t.Run(`GetPolicyEvaluators fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetPartialResultsEvaluators(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetPartialResultsEvaluators returns PartialResultsEvaluators from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), PartialResultsEvaluatorConfigKey{}, PartialResultsEvaluators{})
		opaEval, err := GetPartialResultsEvaluators(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, opaEval != nil, "OPA Module config not found.")
	})
}

func TestAdaptOASSpec(t *testing.T) {
	testCases := []struct {
		name     string
		input    *OpenAPISpec
		expected *OpenAPISpec
	}{
		{
			name: "single path",
			input: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req",
								ResourceFilter: ResourceFilter{
									RowFilter: RowFilterConfiguration{
										Enabled:   true,
										HeaderKey: "header",
									},
								},
								ResponseFilter: ResponseFilterConfiguration{
									Policy: "allow_res",
								},
							},
						},
					},
				},
			},
			expected: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req",
									GenerateQuery: true,
									QueryOptions: QueryOptions{
										HeaderName: "header",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple paths",
			input: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req",
								ResourceFilter: ResourceFilter{
									RowFilter: RowFilterConfiguration{
										Enabled:   true,
										HeaderKey: "header",
									},
								},
								ResponseFilter: ResponseFilterConfiguration{
									Policy: "allow_res",
								},
							},
						},
						"post": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req_post",
								ResourceFilter: ResourceFilter{
									RowFilter: RowFilterConfiguration{
										Enabled: false,
									},
								},
								ResponseFilter: ResponseFilterConfiguration{
									Policy: "allow_res_post",
								},
							},
						},
					},
					"/path-with-old-perm-2": PathVerbs{
						"patch": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req_patch",
							},
						},
					},
				},
			},
			expected: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req",
									GenerateQuery: true,
									QueryOptions: QueryOptions{
										HeaderName: "header",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res",
								},
							},
						},
						"post": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req_post",
									GenerateQuery: false,
									QueryOptions: QueryOptions{
										HeaderName: "",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res_post",
								},
							},
						},
					},
					"/path-with-old-perm-2": PathVerbs{
						"patch": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName: "allow_req_patch",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "hybrid configuration preserves new one",
			input: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req",
								ResourceFilter: ResourceFilter{
									RowFilter: RowFilterConfiguration{
										Enabled:   true,
										HeaderKey: "header",
									},
								},
								ResponseFilter: ResponseFilterConfiguration{
									Policy: "allow_res",
								},
							},
						},
						"post": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req_post_OLD_CONF",
								ResourceFilter: ResourceFilter{
									RowFilter: RowFilterConfiguration{
										Enabled: false,
									},
								},
								ResponseFilter: ResponseFilterConfiguration{
									Policy: "allow_res_post_OLD_CONF",
								},
							},
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req_post",
									GenerateQuery: false,
									QueryOptions: QueryOptions{
										HeaderName: "",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res_post",
								},
							},
						},
					},
					"/path-with-old-perm-2": PathVerbs{
						"patch": VerbConfig{
							PermissionV1: &XPermission{
								AllowPermission: "allow_req_patch",
							},
						},
					},
				},
			},
			expected: &OpenAPISpec{
				Paths: OpenAPIPaths{
					"/path-with-old-perm": PathVerbs{
						"get": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req",
									GenerateQuery: true,
									QueryOptions: QueryOptions{
										HeaderName: "header",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res",
								},
							},
						},
						"post": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName:    "allow_req_post",
									GenerateQuery: false,
									QueryOptions: QueryOptions{
										HeaderName: "",
									},
								},
								ResponseFlow: ResponseFlow{
									PolicyName: "allow_res_post",
								},
							},
						},
					},
					"/path-with-old-perm-2": PathVerbs{
						"patch": VerbConfig{
							PermissionV1: nil,
							PermissionV2: &RondConfig{
								RequestFlow: RequestFlow{
									PolicyName: "allow_req_patch",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			adaptOASSpec(testCase.input)
			assert.DeepEqual(t, testCase.input, testCase.expected)

			for path, pathConfig := range testCase.input.Paths {
				for verb, verbConfig := range pathConfig {
					assert.Assert(t, verbConfig.PermissionV1 == nil, "Unexpected non-nil conf for %s %s", verb, path)
				}
			}
		})
	}
}
