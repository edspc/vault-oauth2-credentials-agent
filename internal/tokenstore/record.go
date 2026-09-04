// Package tokenstore maps OAuth2 tokens onto KV v2 secrets in Vault.
package tokenstore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
)

// Field names of the stored secret. They are part of the contract with the
// consumers that read the secret directly from Vault.
const (
	FieldAccessToken  = "access_token"
	FieldRefreshToken = "refresh_token"
	FieldTokenType    = "token_type"
	FieldExpiry       = "expiry"
	FieldScope        = "scope"
	FieldObtainedAt   = "obtained_at"
	FieldUpdatedAt    = "updated_at"
	FieldEntryID      = "entry_id"
	FieldExtra        = "extra"
)

// Record is the credential as stored in Vault.
type Record struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	// Expiry is zero when the provider did not report an expiry time.
	Expiry time.Time
	Scope  string
	// ObtainedAt is when the credential was last authorized by a user; it
	// survives refreshes.
	ObtainedAt time.Time
	// UpdatedAt is when the secret was last written.
	UpdatedAt time.Time
	EntryID   string
	// Extra carries the provider fields that have no dedicated column, such
	// as id_token.
	Extra map[string]any
}

// Token converts the record back into an OAuth2 token.
func (r *Record) Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  r.AccessToken,
		TokenType:    r.TokenType,
		RefreshToken: r.RefreshToken,
		Expiry:       r.Expiry,
		Scope:        r.Scope,
		Extra:        r.Extra,
	}
}

// encode renders the record as the data block of a KV v2 secret.
func (r *Record) encode() (map[string]any, error) {
	data := map[string]any{
		FieldAccessToken: r.AccessToken,
		FieldTokenType:   r.TokenType,
		FieldScope:       r.Scope,
		FieldEntryID:     r.EntryID,
		FieldObtainedAt:  formatTime(r.ObtainedAt),
		FieldUpdatedAt:   formatTime(r.UpdatedAt),
		FieldExpiry:      formatTime(r.Expiry),
	}
	if r.RefreshToken != "" {
		data[FieldRefreshToken] = r.RefreshToken
	}
	if len(r.Extra) > 0 {
		encoded, err := json.Marshal(r.Extra)
		if err != nil {
			return nil, fmt.Errorf("tokenstore: encode extra fields: %w", err)
		}
		data[FieldExtra] = string(encoded)
	}
	return data, nil
}

// decodeRecord parses the data block of a KV v2 secret. Unknown fields are
// ignored so that a secret written by a newer version still loads.
func decodeRecord(data map[string]any) (*Record, error) {
	rec := &Record{
		AccessToken:  stringValue(data[FieldAccessToken]),
		RefreshToken: stringValue(data[FieldRefreshToken]),
		TokenType:    stringValue(data[FieldTokenType]),
		Scope:        stringValue(data[FieldScope]),
		EntryID:      stringValue(data[FieldEntryID]),
	}
	var err error
	if rec.Expiry, err = parseTime(FieldExpiry, data[FieldExpiry]); err != nil {
		return nil, err
	}
	if rec.ObtainedAt, err = parseTime(FieldObtainedAt, data[FieldObtainedAt]); err != nil {
		return nil, err
	}
	if rec.UpdatedAt, err = parseTime(FieldUpdatedAt, data[FieldUpdatedAt]); err != nil {
		return nil, err
	}
	if raw := stringValue(data[FieldExtra]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &rec.Extra); err != nil {
			return nil, fmt.Errorf("tokenstore: decode %s: %w", FieldExtra, err)
		}
	}
	return rec, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(field string, v any) (time.Time, error) {
	s := stringValue(v)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("tokenstore: decode %s: %w", field, err)
	}
	return t, nil
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}
