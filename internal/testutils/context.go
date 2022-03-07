package testutils

import (
	"context"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mocks"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
	"git.tools.mia-platform.eu/platform/core/rbac-service/opaevaluator"
	"git.tools.mia-platform.eu/platform/core/rbac-service/openapi"
)

func CreateContext(
	t *testing.T,
	originalCtx context.Context,
	env config.EnvironmentVariables,
	mongoClient *mocks.MongoClientMock,
	permission *openapi.XPermission,
	opaModuleConfig *opaevaluator.OPAModuleConfig,
	partialResultEvaluators opaevaluator.PartialResultsEvaluators,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, config.EnvKey{}, env)
	partialContext = context.WithValue(partialContext, openapi.XPermissionKey{}, permission)
	partialContext = context.WithValue(partialContext, opaevaluator.OPAModuleConfigKey{}, opaModuleConfig)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}
	partialContext = context.WithValue(partialContext, opaevaluator.PartialResultsEvaluatorConfigKey{}, partialResultEvaluators)

	return partialContext
}
