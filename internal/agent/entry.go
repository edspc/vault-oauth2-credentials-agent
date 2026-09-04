// Package agent holds the runtime model shared by the HTTP API and the
// background refresher: the credential entries built from the configuration
// and the observable status of each of them.
package agent

import (
	"fmt"
	"net/http"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/config"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/tokenstore"
)

// Entry is a configured credential together with its OAuth2 client.
type Entry struct {
	ID string
	// PKCE reports whether the authorization request carries a code challenge.
	PKCE     bool
	Location tokenstore.Location
	Client   *oauth2.Client
}

// BuildEntries turns the configuration into runtime entries. The configuration
// is expected to have been validated already; errors here are programming or
// wiring mistakes rather than user input problems.
func BuildEntries(cfg *config.Config, httpClient *http.Client) ([]Entry, error) {
	entries := make([]Entry, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		style, err := oauth2.ParseAuthStyle(e.AuthStyle)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", e.ID, err)
		}
		client := oauth2.NewClient(oauth2.Config{
			ClientID:        e.ClientID,
			ClientSecret:    e.ClientSecret,
			AuthURL:         e.AuthURL,
			TokenURL:        e.TokenURL,
			RedirectURL:     e.RedirectURL,
			Scopes:          e.Scopes,
			ExtraAuthParams: e.ExtraAuthParams,
			AuthStyle:       style,
		}, oauth2.WithHTTPClient(httpClient))

		entries = append(entries, Entry{
			ID:       e.ID,
			PKCE:     e.PKCEEnabled(),
			Location: tokenstore.Location{Mount: e.Vault.Mount, Path: e.Vault.Path},
			Client:   client,
		})
	}
	return entries, nil
}
