/*
 * Copyright 2019 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/utils"
	"git.tools.mia-platform.eu/platform/core/rbac-service/openapi"
	"git.tools.mia-platform.eu/platform/core/rbac-service/standalone"

	"github.com/gorilla/mux"
)

func addStandaloneRoutes(router *mux.Router) {
	router.HandleFunc("/revoke/bindings/resource/{resourceType}", standalone.RevokeHandler)
	router.HandleFunc("/grant/bindings/resource/{resourceType}", standalone.GrantHandler)
}

func setupRoutes(router *mux.Router, oas *openapi.OpenAPISpec, env config.EnvironmentVariables) {
	var documentationPermission string
	documentationPathInOAS := oas.Paths[env.TargetServiceOASPath]
	if documentationPathInOAS != nil {
		if getVerb, ok := documentationPathInOAS[strings.ToLower(http.MethodGet)]; ok {
			documentationPermission = getVerb.Permission.AllowPermission
		}
	}

	// NOTE: The following sort is required by mux router because it expects
	// routes to be registered in the proper order
	paths := make([]string, 0)
	for path := range oas.Paths {
		paths = append(paths, path)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))

	for _, path := range paths {
		pathToRegister := path
		if env.Standalone {
			pathToRegister = fmt.Sprintf("%s%s", env.PathPrefixStandalone, path)
		}
		if utils.Contains(statusRoutes, pathToRegister) {
			continue
		}
		if strings.Contains(pathToRegister, "*") {
			pathWithoutAsterisk := strings.ReplaceAll(pathToRegister, "*", "")
			router.PathPrefix(utils.ConvertPathVariablesToBrackets(pathWithoutAsterisk)).HandlerFunc(rbacHandler)
			continue
		}
		if path == env.TargetServiceOASPath && documentationPermission == "" {
			router.HandleFunc(utils.ConvertPathVariablesToBrackets(pathToRegister), alwaysProxyHandler)
			continue
		}
		router.HandleFunc(utils.ConvertPathVariablesToBrackets(pathToRegister), rbacHandler)
	}
	if documentationPathInOAS == nil {
		router.HandleFunc(utils.ConvertPathVariablesToBrackets(env.TargetServiceOASPath), alwaysProxyHandler)
	}
	// FIXME: All the routes don't inserted above are anyway handled by rbacHandler.
	//        Maybe the code above can be cleaned.
	router.PathPrefix(fmt.Sprintf("%s/", env.PathPrefixStandalone)).HandlerFunc(rbacHandler)
}
