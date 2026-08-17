package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// APIKeyIDFromToken reads an API key's own ID out of the key.
//
// A Temporal Cloud API key is a JWT issued by temporal.io, and its payload
// carries the key's ID in the "key_id" claim (repeated as "jti"). That is the
// same ID the Cloud Ops API uses for GetApiKey and DeleteApiKey, so a token is
// self-describing: given one, this engine can name the key it belongs to
// without asking Temporal Cloud and without an operator looking it up.
//
// That matters because rotate-root deletes the key it replaces, and it can
// only do so by ID. Deriving the ID here means the value is correct by
// construction — it came from the very token being stored — where an
// operator-supplied one could name any key at all.
//
// The signature is deliberately not verified. This is not an authentication
// decision: the token is the engine's own credential, obtained from the
// operator through Vault's authenticated API, and Temporal Cloud validates it
// on every call made with it. All that is wanted here is an identifier the
// holder already possesses, so parsing the payload is sufficient and avoids
// needing Temporal Cloud's signing keys.
func APIKeyIDFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf(
			"%w: api key is not a JWT (got %d dot-separated segments, want 3)",
			ErrInvalidArgument, len(parts))
	}

	// JWTs use unpadded base64url, but tolerate padding rather than failing on
	// a token that carries it.
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", fmt.Errorf("%w: decoding the api key payload: %s", ErrInvalidArgument, err)
	}

	var claims struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("%w: parsing the api key payload: %s", ErrInvalidArgument, err)
	}
	if claims.KeyID == "" {
		return "", fmt.Errorf("%w: the api key payload has no key_id claim", ErrInvalidArgument)
	}

	return claims.KeyID, nil
}
