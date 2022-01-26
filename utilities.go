package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
)

const JSONContentTypeHeader = "application/json"

func shouldParseJSONBody(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("content-type"), JSONContentTypeHeader)
}

func failResponse(w http.ResponseWriter, technicalError, businessError string) {
	failResponseWithCode(w, http.StatusInternalServerError, technicalError, businessError)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, technicalError, businessError string) {
	w.WriteHeader(statusCode)
	content, err := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Error:      technicalError,
		Message:    businessError,
	})
	if err != nil {
		return
	}
	w.Write(content)
}

func unmarshalHeader(headers http.Header, headerKey string, v interface{}) (bool, error) {
	headerValueStringified := headers.Get(headerKey)
	if headerValueStringified != "" {
		err := json.Unmarshal([]byte(headerValueStringified), &v)
		return err == nil, err
	}
	return false, nil
}
