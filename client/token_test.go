package client

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// jwtWithPayload builds a token shaped like a Temporal Cloud API key. The
// header and signature are filler: nothing here verifies them, and using a
// real key as a fixture would put a live credential in the repository.
func jwtWithPayload(payload string) string {
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"example"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(payload)),
		base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature")),
	}, ".")
}

// The ordinary case, using the claim shape a real Temporal Cloud API key
// carries. The values are synthetic — a real key's claims identify a real
// account, so they do not belong in a fixture even without the signature.
func TestAPIKeyIDFromToken(t *testing.T) {
	token := jwtWithPayload(`{"account_id":"acct1","aud":["temporal.io"],` +
		`"exp":1800000000,"iss":"temporal.io","jti":"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",` +
		`"key_id":"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",` +
		`"sub":"00000000000000000000000000000000"}`)

	got, err := APIKeyIDFromToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" {
		t.Errorf("expected the key_id claim, got %q", got)
	}
}

// Real tokens are unpadded base64url, but a padded one must not be rejected:
// the ID is what rotate-root needs to clean up after itself, and failing to
// read it silently costs that.
func TestAPIKeyIDFromToken_ToleratesPadding(t *testing.T) {
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.URLEncoding.EncodeToString([]byte(`{"key_id":"apikey-123"}`))
	token := header + "." + payload + ".sig"

	got, err := APIKeyIDFromToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "apikey-123" {
		t.Errorf("expected apikey-123, got %q", got)
	}
}

// Every failure must be distinguishable and must name what was wrong, because
// the caller degrades to "id unknown" and has to explain that to an operator.
func TestAPIKeyIDFromToken_Rejects(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantMessage string
	}{
		{
			name:        "not a jwt",
			token:       "tmprl_sk_opaque",
			wantMessage: "not a JWT",
		},
		{
			name:        "payload is not base64",
			token:       "header.!!!not-base64!!!.sig",
			wantMessage: "decoding",
		},
		{
			name:        "payload is not json",
			token:       jwtWithPayload("this is not json"),
			wantMessage: "parsing",
		},
		{
			name:        "no key_id claim",
			token:       jwtWithPayload(`{"iss":"temporal.io","sub":"abc"}`),
			wantMessage: "no key_id claim",
		},
		{
			name:        "empty key_id claim",
			token:       jwtWithPayload(`{"key_id":""}`),
			wantMessage: "no key_id claim",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := APIKeyIDFromToken(tc.token)

			if err == nil {
				t.Fatalf("expected an error, got id %q", got)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("expected ErrInvalidArgument, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Errorf("expected the error to mention %q, got: %v", tc.wantMessage, err)
			}
			if got != "" {
				t.Errorf("expected no id alongside an error, got %q", got)
			}
		})
	}
}
