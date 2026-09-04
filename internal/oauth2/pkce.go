package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ChallengeMethodS256 is the only PKCE method the agent offers; the plain
// method provides no protection against a leaked authorization request.
const ChallengeMethodS256 = "S256"

// GeneratePKCE returns a fresh RFC 7636 code verifier and its S256 challenge.
// The verifier is 43 characters long, the minimum allowed by the spec and the
// result of base64url-encoding 32 random bytes.
func GeneratePKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	return verifier, S256Challenge(verifier), nil
}

// S256Challenge derives the code challenge of a verifier.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
