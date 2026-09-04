package oauth2

import (
	"errors"
	"fmt"
	"strings"
)

// Error codes defined by RFC 6749 that the agent reacts to.
const (
	// ErrCodeInvalidGrant means the authorization code or refresh token is
	// expired, revoked or otherwise no longer usable. It is not retryable:
	// the credential has to go through the authorization flow again.
	ErrCodeInvalidGrant = "invalid_grant"
	// ErrCodeInvalidClient means the client credentials were rejected.
	ErrCodeInvalidClient = "invalid_client"
)

// Error is an error response from an OAuth2 authorization server.
type Error struct {
	Code        string
	Description string
	URI         string
	StatusCode  int
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("oauth2: ")
	if e.Code != "" {
		b.WriteString(e.Code)
	} else {
		b.WriteString("request failed")
	}
	if e.Description != "" {
		fmt.Fprintf(&b, " (%s)", e.Description)
	}
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, " [http %d]", e.StatusCode)
	}
	return b.String()
}

// IsInvalidGrant reports whether err is an invalid_grant response, meaning the
// stored refresh token can no longer be used and re-authorization is required.
func IsInvalidGrant(err error) bool {
	var oauthErr *Error
	return errors.As(err, &oauthErr) && oauthErr.Code == ErrCodeInvalidGrant
}

// isClientAuthRejected reports whether err indicates that the way client
// credentials were presented was not accepted, which is the signal to retry
// with the other authentication style.
func isClientAuthRejected(err error) bool {
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		return false
	}
	return oauthErr.Code == ErrCodeInvalidClient || oauthErr.StatusCode == 401
}
