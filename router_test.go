package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/testutils"
	"git.tools.mia-platform.eu/platform/core/rbac-service/opaevaluator"
	"git.tools.mia-platform.eu/platform/core/rbac-service/openapi"

	"github.com/gorilla/mux"
	"gotest.tools/v3/assert"
)

func TestSetupRoutes(t *testing.T) {
	envs := config.EnvironmentVariables{
		TargetServiceOASPath: "/documentation/json",
	}
	t.Run("expect to register route correctly", func(t *testing.T) {
		router := mux.NewRouter()
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/foo":        openapi.PathVerbs{},
				"/bar":        openapi.PathVerbs{},
				"/foo/bar":    openapi.PathVerbs{},
				"/-/ready":    openapi.PathVerbs{},
				"/-/healthz":  openapi.PathVerbs{},
				"/-/check-up": openapi.PathVerbs{},
			},
		}
		expectedPaths := []string{"/", "/-/check-up", "/-/healthz", "/-/ready", "/bar", "/documentation/json", "/foo", "/foo/bar"}

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		assert.DeepEqual(t, foundPaths, expectedPaths)
	})

	t.Run("expect to register nested route correctly", func(t *testing.T) {
		router := mux.NewRouter()
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/-/ready":    openapi.PathVerbs{},
				"/-/healthz":  openapi.PathVerbs{},
				"/-/check-up": openapi.PathVerbs{},
				// General route
				"/foo/*":          openapi.PathVerbs{},
				"/foo/bar/*":      openapi.PathVerbs{},
				"/foo/bar/nested": openapi.PathVerbs{},
				"/foo/bar/:barId": openapi.PathVerbs{},
			},
		}
		expectedPaths := []string{"/", "/-/ready", "/-/healthz", "/-/check-up", "/foo/", "/foo/bar/", "/foo/bar/nested", "/foo/bar/{barId}", "/documentation/json"}
		sort.Strings(expectedPaths)

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		assert.DeepEqual(t, foundPaths, expectedPaths)
	})

	t.Run("expect to register route correctly in standalone mode", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceOASPath: "/documentation/json",
			Standalone:           true,
			PathPrefixStandalone: "/validate",
		}
		router := mux.NewRouter()
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/documentation/json": openapi.PathVerbs{},
				"/foo/*":              openapi.PathVerbs{},
				"/foo/bar/*":          openapi.PathVerbs{},
				"/foo/bar/nested":     openapi.PathVerbs{},
				"/foo/bar/:barId":     openapi.PathVerbs{},
			},
		}
		expectedPaths := []string{"/validate/", "/validate/documentation/json", "/validate/foo/", "/validate/foo/bar/", "/validate/foo/bar/nested", "/validate/foo/bar/{barId}"}
		sort.Strings(expectedPaths)

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		assert.DeepEqual(t, foundPaths, expectedPaths)
	})
}

var mockOPAModule = &opaevaluator.OPAModuleConfig{
	Name: "example.rego",
	Content: `package policies
todo { true }`,
}
var mockXPermission = &openapi.XPermission{AllowPermission: "todo"}

func TestSetupRoutesIntegration(t *testing.T) {
	oas := openapi.PrepareOASFromFile(t, "./mocks/simplifiedMock.json")
	mockPartialEvaluators, _ := opaevaluator.SetupEvaluators(context.Background(), nil, oas, mockOPAModule)
	envs := config.EnvironmentVariables{}

	t.Run("invokes known API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.URL.Path, "/users/", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "foo=bar", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("invokes unknown API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.URL.Path, "/unknown/path", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "foo=bar", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/unknown/path?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("blocks request on not allowed policy evaluation", func(t *testing.T) {
		var mockOPAModule = &opaevaluator.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		todo { false }`,
		}
		mockPartialEvaluators, _ := opaevaluator.SetupEvaluators(context.Background(), nil, oas, mockOPAModule)
		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden)
	})

	t.Run("blocks request on policy evaluation error", func(t *testing.T) {

		var mockOPAModule = &opaevaluator.OPAModuleConfig{
			Content: "FAILING POLICY!!!!",
		}
		mockPartialEvaluators, _ := opaevaluator.SetupEvaluators(context.Background(), nil, oas, mockOPAModule)

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)
	})

	t.Run("invokes the API not explicitly set in the oas file", func(t *testing.T) {
		oas := openapi.PrepareOASFromFile(t, "./mocks/nestedPathsConfig.json")

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/foo/route-not-registered-explicitly", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("invokes a specific API within a nested path", func(t *testing.T) {
		oas := openapi.PrepareOASFromFile(t, "./mocks/nestedPathsConfig.json")

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := testutils.CreateContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/foo/bar/nested", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})
}
