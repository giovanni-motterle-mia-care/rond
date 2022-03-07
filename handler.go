package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mongoclient"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/opatranslator"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/openapi"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/utils"
	"git.tools.mia-platform.eu/platform/core/rbac-service/opaevaluator"

	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"
const NO_PERMISSIONS_ERROR_MESSAGE = "You do not have permissions to access this feature, contact the project administrator for more information."

func ReverseProxyOrResponse(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	permission *openapi.XPermission,
	partialResultsEvaluators opaevaluator.PartialResultsEvaluators,
) {
	if env.Standalone {
		w.Header().Set(BASE_ROW_FILTER_HEADER_KEY, req.Header.Get(BASE_ROW_FILTER_HEADER_KEY))
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
		return
	}
	ReverseProxy(logger, env, w, req, permission, partialResultsEvaluators)
}

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	env, err := config.GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		utils.FailResponse(w, "No environment found in context", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	permission, err := openapi.GetXPermission(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no policy permission found in context")
		utils.FailResponse(w, "no policy permission found in context", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	partialResultEvaluators, err := opaevaluator.GetPartialResultsEvaluators(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no partialResult evaluators found in context")
		utils.FailResponse(w, "no partialResult evaluators found in context", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if err := EvaluateRequest(req, env, w, partialResultEvaluators, permission); err != nil {
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, permission, partialResultEvaluators)
}

func EvaluateRequest(
	req *http.Request,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	partialResultsEvaluators opaevaluator.PartialResultsEvaluators,
	permission *openapi.XPermission,
) error {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	userInfo, err := mongoclient.RetrieveUserBindingsAndRoles(logger, req, env)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "user bindings retrieval failed", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	input, err := opaevaluator.CreateRegoQueryInput(req, env, userInfo, nil)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed rego query input creation")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "RBAC input creation failed", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	var evaluatorAllowPolicy *opaevaluator.OPAEvaluator
	if !permission.ResourceFilter.RowFilter.Enabled {
		evaluatorAllowPolicy, err = partialResultsEvaluators.GetEvaluatorFromPolicy(requestContext, permission.AllowPermission, input)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot find policy evaluator")
			utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed partial evaluator retrieval", types.GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	} else {
		evaluatorAllowPolicy, err = opaevaluator.CreateQueryEvaluator(requestContext, logger, req, env, permission.AllowPermission, input, nil)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot create evaluator")
			utils.FailResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluator creation failed", NO_PERMISSIONS_ERROR_MESSAGE)
			return err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(logger, permission)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && utils.HasApplicationJSONContentType(req.Header) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set(utils.ContentTypeHeaderKey, utils.JSONContentTypeHeader)
			w.Write([]byte("[]"))
			return err
		}

		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("RBAC policy evaluation failed")
		utils.FailResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed", NO_PERMISSIONS_ERROR_MESSAGE)
		return err
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
			utils.FailResponseWithCode(w, http.StatusForbidden, "Error while marshaling row filter query", types.GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	}

	queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
	if permission.ResourceFilter.RowFilter.HeaderKey != "" {
		queryHeaderKey = permission.ResourceFilter.RowFilter.HeaderKey
	}
	if query != nil {
		req.Header.Set(queryHeaderKey, string(queryToProxy))
	}
	return nil
}

func ReverseProxy(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	permission *openapi.XPermission,
	partialResultsEvaluators opaevaluator.PartialResultsEvaluators,
) {
	targetHostFromEnv := env.TargetServiceHost
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Host = targetHostFromEnv
			req.URL.Scheme = URL_SCHEME
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
		},
	}
	// Check on nil is performed to proxy the oas documentation path
	if permission == nil || permission.ResponseFilter.Policy == "" {
		proxy.ServeHTTP(w, req)
		return
	}
	proxy.Transport = &OPATransport{
		http.DefaultTransport,
		req.Context(),
		logger,
		req,
		env,
		permission,
		partialResultsEvaluators,
	}
	proxy.ServeHTTP(w, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(req.Context())
	env, err := config.GetEnv(requestContext)
	if err != nil {
		glogger.Get(requestContext).WithError(err).Error("no env found in context")
		utils.FailResponse(w, "no environment found in context", types.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, nil, nil)
}
