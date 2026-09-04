package vault

import (
	"errors"
	"fmt"
	"strings"
)

// ErrSecretNotFound is returned when a KV v2 path holds no readable version.
var ErrSecretNotFound = errors.New("vault: secret not found")

// ErrCASMismatch is returned when a check-and-set write lost a race with a
// concurrent writer. The caller should re-read and retry.
var ErrCASMismatch = errors.New("vault: check-and-set version mismatch")

// APIError is a non-2xx response from the Vault HTTP API.
type APIError struct {
	StatusCode int
	Errors     []string
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("vault: request failed with http %d", e.StatusCode)
	}
	return fmt.Sprintf("vault: http %d: %s", e.StatusCode, strings.Join(e.Errors, "; "))
}

// isPermissionDenied reports whether the request failed because the client
// token was rejected, which is the signal to authenticate again.
func isPermissionDenied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		(apiErr.StatusCode == 403 || apiErr.StatusCode == 401)
}

// isCASMismatch recognises the check-and-set failure, which Vault reports as a
// plain 400 with a descriptive message rather than a dedicated status code.
func (e *APIError) isCASMismatch() bool {
	for _, msg := range e.Errors {
		if strings.Contains(msg, "check-and-set parameter") {
			return true
		}
	}
	return false
}
