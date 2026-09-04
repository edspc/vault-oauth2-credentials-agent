package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedNow }

func testConfig(tokenURL string) Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      "https://provider.example.com/authorize",
		TokenURL:     tokenURL,
		RedirectURL:  "https://agent.example.com/callback",
		Scopes:       []string{"repo", "read:org"},
	}
}

func TestAuthCodeURL(t *testing.T) {
	cfg := testConfig("https://provider.example.com/token")
	cfg.ExtraAuthParams = map[string]string{"access_type": "offline"}
	client := NewClient(cfg)

	raw, err := client.AuthCodeURL("state-value", "challenge-value")
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}

	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-id",
		"redirect_uri":          "https://agent.example.com/callback",
		"scope":                 "repo read:org",
		"state":                 "state-value",
		"code_challenge":        "challenge-value",
		"code_challenge_method": ChallengeMethodS256,
		"access_type":           "offline",
	}
	got := u.Query()
	for key, value := range want {
		if got.Get(key) != value {
			t.Errorf("query %q = %q, want %q", key, got.Get(key), value)
		}
	}
}

func TestAuthCodeURLWithoutPKCE(t *testing.T) {
	client := NewClient(testConfig("https://provider.example.com/token"))

	raw, err := client.AuthCodeURL("state-value", "")
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}
	u, _ := url.Parse(raw)
	if u.Query().Has("code_challenge") {
		t.Error("code_challenge is present, want it omitted when PKCE is disabled")
	}
}

func TestExchangeJSONResponse(t *testing.T) {
	var gotForm url.Values
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","refresh_token":"rt","token_type":"Bearer",`+
			`"expires_in":3600,"scope":"repo","id_token":"idt"}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	token, err := client.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	if gotForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", gotForm.Get("grant_type"))
	}
	if gotForm.Get("code") != "the-code" {
		t.Errorf("code = %q, want the-code", gotForm.Get("code"))
	}
	if gotForm.Get("code_verifier") != "the-verifier" {
		t.Errorf("code_verifier = %q, want the-verifier", gotForm.Get("code_verifier"))
	}
	if gotForm.Has("client_secret") {
		t.Error("client_secret sent in the body, want it in the Basic header")
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("Authorization = %q, want a Basic header", gotAuth)
	}

	if token.AccessToken != "at" || token.RefreshToken != "rt" || token.TokenType != "Bearer" {
		t.Errorf("token = %+v, want at/rt/Bearer", token)
	}
	if want := fixedNow.Add(time.Hour); !token.Expiry.Equal(want) {
		t.Errorf("Expiry = %s, want %s", token.Expiry, want)
	}
	if token.Extra["id_token"] != "idt" {
		t.Errorf("Extra[id_token] = %v, want idt", token.Extra["id_token"])
	}
	if _, ok := token.Extra["access_token"]; ok {
		t.Error("Extra contains access_token, want known fields excluded")
	}
}

func TestExchangeFormEncodedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		io.WriteString(w, "access_token=at&scope=repo%2Cread%3Aorg&token_type=bearer")
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	token, err := client.Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if token.AccessToken != "at" {
		t.Errorf("AccessToken = %q, want at", token.AccessToken)
	}
	if token.Scope != "repo,read:org" {
		t.Errorf("Scope = %q, want repo,read:org", token.Scope)
	}
	if !token.Expiry.IsZero() {
		t.Errorf("Expiry = %s, want zero when expires_in is absent", token.Expiry)
	}
}

func TestExchangeExpiresInAsString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","expires_in":"120"}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	token, err := client.Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if want := fixedNow.Add(2 * time.Minute); !token.Expiry.Equal(want) {
		t.Errorf("Expiry = %s, want %s", token.Expiry, want)
	}
}

func TestRefreshSendsRefreshToken(t *testing.T) {
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"new-at","expires_in":60}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	token, err := client.Refresh(context.Background(), "the-refresh-token")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", gotForm.Get("grant_type"))
	}
	if gotForm.Get("refresh_token") != "the-refresh-token" {
		t.Errorf("refresh_token = %q, want the-refresh-token", gotForm.Get("refresh_token"))
	}
	if token.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q, want new-at", token.AccessToken)
	}
	if token.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty so the caller keeps the old one", token.RefreshToken)
	}
}

func TestRefreshRejectsEmptyToken(t *testing.T) {
	client := NewClient(testConfig("https://provider.example.com/token"))
	if _, err := client.Refresh(context.Background(), ""); err == nil {
		t.Fatal("Refresh() error = nil, want an error for an empty refresh token")
	}
}

func TestInvalidGrantIsRecognised(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"token revoked"}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	_, err := client.Refresh(context.Background(), "rt")
	if err == nil {
		t.Fatal("Refresh() error = nil, want invalid_grant")
	}
	if !IsInvalidGrant(err) {
		t.Errorf("IsInvalidGrant(%v) = false, want true", err)
	}
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error %v is not an *Error", err)
	}
	if oauthErr.Description != "token revoked" {
		t.Errorf("Description = %q, want %q", oauthErr.Description, "token revoked")
	}
	if !strings.Contains(oauthErr.Error(), "invalid_grant") {
		t.Errorf("Error() = %q, want it to mention invalid_grant", oauthErr.Error())
	}
}

func TestAutoAuthStyleFallsBackToParams(t *testing.T) {
	var headerAttempts, paramAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if _, _, ok := r.BasicAuth(); ok {
			headerAttempts++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		if form.Get("client_secret") != "client-secret" {
			t.Errorf("client_secret = %q, want it in the body", form.Get("client_secret"))
		}
		paramAttempts++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","expires_in":60}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	if _, err := client.Exchange(context.Background(), "code", ""); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if headerAttempts != 1 || paramAttempts != 1 {
		t.Fatalf("attempts header=%d params=%d, want 1 and 1", headerAttempts, paramAttempts)
	}

	// The working style is remembered, so the next call skips the header.
	if _, err := client.Refresh(context.Background(), "rt"); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if headerAttempts != 1 {
		t.Errorf("headerAttempts = %d, want the failing style not to be retried", headerAttempts)
	}
	if paramAttempts != 2 {
		t.Errorf("paramAttempts = %d, want 2", paramAttempts)
	}
}

func TestPinnedAuthStyleIsNotRetried(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.AuthStyle = AuthStyleInHeader
	client := NewClient(cfg, WithClock(fixedClock))
	if _, err := client.Exchange(context.Background(), "code", ""); err == nil {
		t.Fatal("Exchange() error = nil, want invalid_client")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 for a pinned auth style", attempts)
	}
}

func TestPublicClientSendsClientIDInBody(t *testing.T) {
	var gotForm url.Values
	var hadBasicAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		_, _, hadBasicAuth = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at"}`)
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.ClientSecret = ""
	client := NewClient(cfg, WithClock(fixedClock))
	if _, err := client.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if hadBasicAuth {
		t.Error("Basic auth used, want none without a client secret")
	}
	if gotForm.Get("client_id") != "client-id" {
		t.Errorf("client_id = %q, want client-id", gotForm.Get("client_id"))
	}
	if gotForm.Has("client_secret") {
		t.Error("client_secret sent, want it omitted when empty")
	}
}

func TestMissingAccessTokenIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"token_type":"Bearer"}`)
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	_, err := client.Exchange(context.Background(), "code", "")
	if err == nil || !strings.Contains(err.Error(), "no access_token") {
		t.Fatalf("Exchange() error = %v, want a missing access_token error", err)
	}
}

func TestNonOAuthErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>gateway timeout</html>")
	}))
	defer server.Close()

	client := NewClient(testConfig(server.URL), WithClock(fixedClock))
	_, err := client.Exchange(context.Background(), "code", "")
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error = %v, want an *Error", err)
	}
	if oauthErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502", oauthErr.StatusCode)
	}
	if IsInvalidGrant(err) {
		t.Error("IsInvalidGrant() = true, want false")
	}
}

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("len(verifier) = %d, want between 43 and 128 per RFC 7636", len(verifier))
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Errorf("challenge = %q, want %q", challenge, want)
	}

	other, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if other == verifier {
		t.Error("two verifiers are identical, want them to be random")
	}
}

func TestParseAuthStyle(t *testing.T) {
	tests := map[string]AuthStyle{
		"":       AuthStyleAuto,
		"auto":   AuthStyleAuto,
		"header": AuthStyleInHeader,
		"params": AuthStyleInParams,
	}
	for input, want := range tests {
		got, err := ParseAuthStyle(input)
		if err != nil {
			t.Errorf("ParseAuthStyle(%q) error = %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAuthStyle(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := ParseAuthStyle("basic"); err == nil {
		t.Error("ParseAuthStyle(\"basic\") error = nil, want an error")
	}
}

func TestTokenExpired(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		leeway time.Duration
		want   bool
	}{
		{"no expiry", time.Time{}, time.Minute, false},
		{"far in the future", fixedNow.Add(time.Hour), time.Minute, false},
		{"within the leeway", fixedNow.Add(30 * time.Second), time.Minute, true},
		{"already past", fixedNow.Add(-time.Second), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{Expiry: tt.expiry}
			if got := token.Expired(fixedNow, tt.leeway); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}
