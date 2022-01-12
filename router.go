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
	"net/http"
	"rbac-service/internal/utils"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
)

var ignoredRoutes = []string{"/-/healthz", "/-/ready", "/-/check-up"}
var rx = regexp.MustCompile(`\/:(\w+)`)

func setupRoutes(router *mux.Router, oas *OpenAPISpec, env EnvironmentVariables) {
	var documentationPermission string
	documentationPathInOAS := oas.Paths[env.TargetServiceOASPath]
	if documentationPathInOAS != nil {
		if getVerb, ok := documentationPathInOAS[strings.ToLower(http.MethodGet)]; ok {
			documentationPermission = getVerb.Permission.AllowPermission
		}
	}

	for key := range oas.Paths {
		if utils.Contains(ignoredRoutes, key) {
			continue
		}
		if strings.Contains(key, "*") {
			pathWithoutAsterisk := strings.ReplaceAll(key, "*", "")
			router.PathPrefix(convertPathVariables(pathWithoutAsterisk)).HandlerFunc(rbacHandler)
			continue
		}
		if key == env.TargetServiceOASPath && documentationPermission == "" {
			router.HandleFunc(convertPathVariables(key), alwaysProxyHandler)
			continue
		}
		router.HandleFunc(convertPathVariables(key), rbacHandler)
	}
	if documentationPathInOAS == nil {
		router.HandleFunc(convertPathVariables(env.TargetServiceOASPath), alwaysProxyHandler)
	}
	// FIXME: All the routes don't inserted above are anyway handled by rbacHandler.
	//        Maybe the code above can be cleaned.
	router.PathPrefix("/").HandlerFunc(rbacHandler)
}

func convertPathVariables(path string) string {
	return rx.ReplaceAllString(path, "/{$1}")
}
