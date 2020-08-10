package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/rand"
	"time"
)

const (
	minVerifierLength = 43
	maxVerifierLength = 128
	characters        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-~"
)

var errInvalidLength = errors.New("invalid verifier length")

// Auth can be configured to create a custom code verifier and challenge.
type Auth struct {
	verifierLength int
	encoded        bool
}

// DefaultAuth returns default auth object which sets verifier to max length and URL encodes the values.
func DefaultAuth() Auth {
	return Auth{
		verifierLength: maxVerifierLength,
		encoded:        true,
	}
}

// CustomAuth returns a custom auth object along with an error if there was a problem with creation.
func CustomAuth(verifierLength int, encoded bool) (Auth, error) {
	if verifierLength < minVerifierLength || verifierLength > maxVerifierLength {
		return Auth{}, errInvalidLength
	}

	return Auth{
		verifierLength: verifierLength,
		encoded:        encoded,
	}, nil
}

// GenerateCodeVerifier returns a valid code verifier as a string.
func (pa Auth) GenerateCodeVerifier() string {
	var codeVerifier = make([]byte, pa.verifierLength)

	rand.Seed(time.Now().UTC().UnixNano())

	for i := 0; i < pa.verifierLength; i++ {
		codeVerifier[i] = characters[rand.Intn(len(characters))]
	}

	if pa.encoded {
		return urlEncode(codeVerifier)
	}

	return string(codeVerifier)
}

// GenerateCodeChallenge returns a valid code challenge as a string.
func (pa Auth) GenerateCodeChallenge(codeVerifier string) string {
	verifier := []byte(codeVerifier)
	hashedVerifier := sha256.Sum256(verifier)

	if pa.encoded {
		return urlEncode(hashedVerifier[:])
	}

	return string(hashedVerifier[:])
}

func urlEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
