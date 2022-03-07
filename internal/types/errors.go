package types

import "errors"

const GENERIC_BUSINESS_ERROR_MESSAGE = "Internal server error, please try again later"

var (
	ErrRequestFailed  = errors.New("request failed")
	ErrFileLoadFailed = errors.New("file loading failed")
)
