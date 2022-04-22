package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/opatranslator"
	"git.tools.mia-platform.eu/platform/core/rbac-service/types"

	"git.tools.mia-platform.eu/platform/core/rbac-service/custom_builtins"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Evaluator interface {
	Eval(ctx context.Context) (rego.ResultSet, error)
	Partial(ctx context.Context) (*rego.PartialQueries, error)
}

var unknowns = []string{"data.resources"}

type OPAEvaluator struct {
	PolicyEvaluator Evaluator
	Context         context.Context
}
type PartialResultsEvaluatorConfigKey struct{}

type PartialResultsEvaluators map[string]PartialEvaluator

type PartialEvaluator struct {
	PartialEvaluator *rego.PartialResult
}

func setupEvaluators(ctx context.Context, mongoClient types.IMongoClient, oas *OpenAPISpec, opaModuleConfig *OPAModuleConfig, env config.EnvironmentVariables) (PartialResultsEvaluators, error) {
	policyEvaluators := PartialResultsEvaluators{}
	for path, OASContent := range oas.Paths {
		for verb, xPermission := range OASContent {

			allowPolicy := xPermission.Permission.AllowPermission
			responsePolicy := xPermission.Permission.ResponseFilter.Policy

			glogger.Get(ctx).Infof("precomputing rego queries for API: %s %s. Allow policy: %s. Response policy: %s.", verb, path, allowPolicy, responsePolicy)
			if allowPolicy == "" {
				// allow policy is required, if missing assume the API has no x-permission configuration.
				continue
			}

			if _, ok := policyEvaluators[allowPolicy]; !ok {
				glogger.Get(ctx).Infof("precomputing rego query for allow policy: %s", allowPolicy)

				allowPolicyEvaluatorTime := time.Now()
				allowPartialResultEvaluator, err := NewPartialResultEvaluator(ctx, allowPolicy, opaModuleConfig, mongoClient, env)
				if err != nil {
					return nil, fmt.Errorf("error during evaluator creation: %s", err.Error())
				}
				glogger.Get(ctx).Infof("computed rego query for allow policy: %s in %s", allowPolicy, time.Since(allowPolicyEvaluatorTime))

				policyEvaluators[allowPolicy] = PartialEvaluator{
					PartialEvaluator: allowPartialResultEvaluator,
				}
			}

			if responsePolicy != "" {
				if _, ok := policyEvaluators[responsePolicy]; !ok {
					glogger.Get(ctx).Infof("precomputing rego query for response filtering policy: %s", responsePolicy)
					responsePolicyEvaluatorTime := time.Now()

					responsePartialResultEvaluator, err := NewPartialResultEvaluator(ctx, responsePolicy, opaModuleConfig, mongoClient, env)
					if err != nil {
						return nil, fmt.Errorf("error during evaluator creation: %s", err.Error())
					}
					glogger.Get(ctx).Tracef("computed rego query for response filtering policy: %s in %s", responsePolicy, time.Since(responsePolicyEvaluatorTime))

					policyEvaluators[responsePolicy] = PartialEvaluator{
						PartialEvaluator: responsePartialResultEvaluator,
					}
				}
			}
		}
	}
	return policyEvaluators, nil
}

func NewPrintHook(w io.Writer, policy string) print.Hook {
	return printHook{
		w:          w,
		policyName: policy,
	}
}

type printHook struct {
	w          io.Writer
	policyName string
}

type LogPrinter struct {
	Level      int    `json:"level"`
	Message    string `json:"msg"`
	Time       int64  `json:"time"`
	PolicyName string `json:"policyName"`
}

func (h printHook) Print(_ print.Context, message string) error {
	structMessage := LogPrinter{
		Level:      10,
		Message:    message,
		Time:       time.Now().UnixNano() / 1000,
		PolicyName: h.policyName,
	}
	msg, err := json.Marshal(structMessage)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(h.w, string(msg))
	return err
}

func NewOPAEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, input []byte, env config.EnvironmentVariables) (*OPAEvaluator, error) {
	inputTerm, err := ast.ParseTerm(string(input))
	if err != nil {
		return nil, fmt.Errorf("failed input parse: %v", err)
	}

	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)
	query := rego.New(
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.ParsedInput(inputTerm.Value),
		rego.Unknowns(unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		rego.EnablePrintStatements(env.LogLevel == config.TraceLogLevel),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		custom_builtins.GetHeaderFunction,
		custom_builtins.MongoFindOne,
		custom_builtins.MongoFindMany,
	)

	return &OPAEvaluator{
		PolicyEvaluator: query,
		Context:         ctx,
	}, nil
}

func createQueryEvaluator(ctx context.Context, logger *logrus.Entry, req *http.Request, env config.EnvironmentVariables, policy string, input []byte, responseBody interface{}) (*OPAEvaluator, error) {
	opaModuleConfig, err := GetOPAModuleConfig(req.Context())
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no OPA module configuration found in context")
		return nil, fmt.Errorf("no OPA module configuration found in context")
	}

	logger.WithFields(logrus.Fields{
		"policyName": policy,
	}).Info("Policy to be evaluated")

	logger.WithFields(logrus.Fields{
		"input": string(input),
	}).Trace("input object passed to the evaluator")

	opaEvaluatorInstanceTime := time.Now()
	evaluator, err := NewOPAEvaluator(ctx, policy, opaModuleConfig, input, env)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		return nil, err
	}
	logger.Tracef("OPA evaluator instantiated in: %+v", time.Since(opaEvaluatorInstanceTime))
	return evaluator, nil
}

func NewPartialResultEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, mongoClient types.IMongoClient, env config.EnvironmentVariables) (*rego.PartialResult, error) {
	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)

	options := []func(*rego.Rego){
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.Unknowns(unknowns),
		rego.EnablePrintStatements(env.LogLevel == config.TraceLogLevel),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
	}
	if mongoClient != nil {
		options = append(options, custom_builtins.MongoFindOne, custom_builtins.MongoFindMany)
	}
	regoInstance := rego.New(options...)

	results, err := regoInstance.PartialResult(ctx)
	return &results, err
}

func (partialEvaluators PartialResultsEvaluators) GetEvaluatorFromPolicy(ctx context.Context, policy string, input []byte, env config.EnvironmentVariables) (*OPAEvaluator, error) {
	if eval, ok := partialEvaluators[policy]; ok {
		inputTerm, err := ast.ParseTerm(string(input))
		if err != nil {
			return nil, fmt.Errorf("failed input parse: %v", err)
		}

		evaluator := eval.PartialEvaluator.Rego(
			rego.ParsedInput(inputTerm.Value),
			rego.EnablePrintStatements(env.LogLevel == config.TraceLogLevel),
			rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		)

		return &OPAEvaluator{
			PolicyEvaluator: evaluator,
			Context:         ctx,
		}, nil
	}
	return nil, fmt.Errorf("policy evaluator not found")
}

func (evaluator *OPAEvaluator) partiallyEvaluate(logger *logrus.Entry) (primitive.M, error) {
	opaEvaluationTime := time.Now()
	partialResults, err := evaluator.PolicyEvaluator.Partial(evaluator.Context)
	if err != nil {
		return nil, fmt.Errorf("policy Evaluation has failed when partially evaluating the query: %s", err.Error())
	}
	logger.Tracef("OPA partial evaluation in: %+v", time.Since(opaEvaluationTime))

	client := opatranslator.OPAClient{}
	q, err := client.ProcessQuery(partialResults)
	if err != nil {
		return nil, err
	}

	logger.WithFields(logrus.Fields{
		"allowed": true,
		"query":   q,
	}).Tracef("policy results and query")

	return q, nil
}

func (evaluator *OPAEvaluator) evaluate(logger *logrus.Entry) (interface{}, error) {
	opaEvaluationTime := time.Now()
	results, err := evaluator.PolicyEvaluator.Eval(evaluator.Context)
	if err != nil {
		return nil, fmt.Errorf("policy Evaluation has failed when evaluating the query: %s", err.Error())
	}
	logger.Tracef("OPA evaluation in: %+v", time.Since(opaEvaluationTime))

	if results.Allowed() {
		logger.WithFields(logrus.Fields{
			"allowed":       results.Allowed(),
			"resultsLength": len(results),
		}).Tracef("policy results")
		return nil, nil
	}

	// The results returned by OPA are a list of Results object with fields:
	// - Expressions: list of list
	// - Bindings: object
	// e.g. [{Expressions:[[map["element": true]]] Bindings:map[]}]
	// Since we are ALWAYS querying ONE specifc policy the result length could not be greater than 1

	if len(results) == 1 {
		if exprs := results[0].Expressions; len(exprs) == 1 {
			if value, ok := exprs[0].Value.([]interface{}); ok && value != nil && len(value) != 0 {
				return value[0], nil
			}
		}
	}
	logger.Error("policy resulted in not allowed")
	return nil, fmt.Errorf("RBAC policy evaluation failed, user is not allowed")
}

func (evaluator *OPAEvaluator) PolicyEvaluation(logger *logrus.Entry, permission *XPermission) (interface{}, primitive.M, error) {
	if permission.ResourceFilter.RowFilter.Enabled {
		query, err := evaluator.partiallyEvaluate(logger)
		return nil, query, err
	}
	dataFromEvaluation, err := evaluator.evaluate(logger)
	if err != nil {
		return nil, nil, err
	}
	return dataFromEvaluation, nil, nil
}

func createRegoQueryInput(req *http.Request, env config.EnvironmentVariables, user types.User, responseBody interface{}) ([]byte, error) {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)
	opaInputCreationTime := time.Now()
	userProperties := make(map[string]interface{})
	_, err := unmarshalHeader(req.Header, env.UserPropertiesHeader, &userProperties)
	if err != nil {
		return nil, fmt.Errorf("user properties header is not valid: %s", err.Error())
	}

	userGroup := make([]string, 0)
	userGroupsNotSplitted := req.Header.Get(env.UserGroupsHeader)
	if userGroupsNotSplitted != "" {
		userGroup = strings.Split(userGroupsNotSplitted, ",")
	}

	input := Input{
		ClientType: req.Header.Get(env.ClientTypeHeader),
		Request: InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: mux.Vars(req),
		},
		Response: InputResponse{
			Body: responseBody,
		},
		User: InputUser{
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
			Properties: userProperties,
			Groups:     userGroup,
		},
	}

	shouldParseJSONBody := hasApplicationJSONContentType(req.Header) &&
		req.ContentLength > 0 &&
		(req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodDelete)

	if shouldParseJSONBody {
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed request body parse: %s", err.Error())
		}
		if err := json.Unmarshal(bodyBytes, &input.Request.Body); err != nil {
			return nil, fmt.Errorf("failed request body deserialization: %s", err.Error())
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed input JSON encode: %v", err)
	}
	logger.Tracef("OPA input rego creation in: %+v", time.Since(opaInputCreationTime))
	return inputBytes, nil
}

func WithPartialResultsEvaluators(requestContext context.Context, evaluators PartialResultsEvaluators) context.Context {
	return context.WithValue(requestContext, PartialResultsEvaluatorConfigKey{}, evaluators)
}

// GetPartialResultsEvaluators can be used by a request handler to get PartialResult evaluator instance from context.
func GetPartialResultsEvaluators(requestContext context.Context) (PartialResultsEvaluators, error) {
	evaluators, ok := requestContext.Value(PartialResultsEvaluatorConfigKey{}).(PartialResultsEvaluators)
	if !ok {
		return nil, fmt.Errorf("no policy evaluators found in request context")
	}

	return evaluators, nil
}
