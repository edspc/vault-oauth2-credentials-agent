package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token is the credential returned by a token endpoint.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	// Expiry is the absolute expiry time of the access token. It is zero when
	// the provider did not return expires_in, in which case the agent cannot
	// know when to refresh and leaves the credential alone.
	Expiry time.Time
	// Scope is the scope actually granted, which may differ from the request.
	Scope string
	// Extra holds any remaining fields of the token response, such as
	// id_token, so that nothing from the provider is silently dropped.
	Extra map[string]any
}

// Expired reports whether the token is known to expire within leeway.
// A token without a known expiry never reports as expired.
func (t *Token) Expired(now time.Time, leeway time.Duration) bool {
	if t.Expiry.IsZero() {
		return false
	}
	return !t.Expiry.After(now.Add(leeway))
}

// fields that are mapped onto Token and therefore excluded from Extra.
var knownTokenFields = map[string]struct{}{
	"access_token": {}, "token_type": {}, "refresh_token": {},
	"expires_in": {}, "scope": {},
	"error": {}, "error_description": {}, "error_uri": {},
}

// parseTokenResponse turns a token endpoint response body into a Token.
// Both JSON and application/x-www-form-urlencoded bodies are accepted: some
// providers, GitHub among them, answer with a form body unless asked otherwise.
func parseTokenResponse(body []byte, contentType string, statusCode int, now time.Time) (*Token, error) {
	values, err := decodeTokenBody(body, contentType)
	if err != nil {
		if statusCode < 200 || statusCode > 299 {
			return nil, &Error{StatusCode: statusCode, Description: httpErrorDescription(body)}
		}
		return nil, err
	}

	if errCode := stringField(values, "error"); errCode != "" {
		return nil, &Error{
			Code:        errCode,
			Description: stringField(values, "error_description"),
			URI:         stringField(values, "error_uri"),
			StatusCode:  statusCode,
		}
	}
	if statusCode < 200 || statusCode > 299 {
		// The body parsed but carries no error object; do not echo it back,
		// it may still contain credential material.
		return nil, &Error{StatusCode: statusCode}
	}

	tok := &Token{
		AccessToken:  stringField(values, "access_token"),
		TokenType:    stringField(values, "token_type"),
		RefreshToken: stringField(values, "refresh_token"),
		Scope:        stringField(values, "scope"),
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("oauth2: token response contains no access_token")
	}
	if raw, ok := values["expires_in"]; ok {
		seconds, err := numberField(raw)
		if err != nil {
			return nil, fmt.Errorf("oauth2: invalid expires_in: %w", err)
		}
		if seconds > 0 {
			tok.Expiry = now.Add(time.Duration(seconds) * time.Second)
		}
	}
	for k, v := range values {
		if _, known := knownTokenFields[k]; known {
			continue
		}
		if tok.Extra == nil {
			tok.Extra = make(map[string]any)
		}
		tok.Extra[k] = v
	}
	return tok, nil
}

func decodeTokenBody(body []byte, contentType string) (map[string]any, error) {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.TrimSpace(strings.ToLower(mediaType))

	trimmed := bytes.TrimSpace(body)
	looksJSON := len(trimmed) > 0 && trimmed[0] == '{'
	if looksJSON || strings.Contains(mediaType, "json") {
		var values map[string]any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&values); err != nil {
			return nil, fmt.Errorf("oauth2: decode json token response: %w", err)
		}
		return values, nil
	}

	query, err := url.ParseQuery(string(trimmed))
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode form token response: %w", err)
	}
	if len(query) == 0 {
		return nil, fmt.Errorf("oauth2: empty token response")
	}
	values := make(map[string]any, len(query))
	for k, v := range query {
		if len(v) > 0 {
			values[k] = v[0]
		}
	}
	return values, nil
}

func stringField(values map[string]any, key string) string {
	v, ok := values[key]
	if !ok {
		return ""
	}
	switch typed := v.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func numberField(v any) (int64, error) {
	switch typed := v.(type) {
	case json.Number:
		return typed.Int64()
	case string:
		if typed == "" {
			return 0, nil
		}
		return strconv.ParseInt(typed, 10, 64)
	case float64:
		return int64(typed), nil
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}

// httpErrorDescription builds a short, bounded description for a non-2xx
// response whose body is not a usable OAuth2 error object.
func httpErrorDescription(body []byte) string {
	const maxLen = 200
	s := strings.TrimSpace(string(body))
	if s == "" {
		return ""
	}
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return strings.Join(strings.Fields(s), " ")
}
