package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"time"
)

func GenerateCodeVerifier() string {
	characters := []byte("1234567890qwertyuiopasdfghjklzxcvbnm_.-~")
	// length := rand.Intn(maxVerifierLength-minVerifierLength) + minVerifierLength
	var codeVerifier = make([]byte, 64)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < 64; i++ {
		codeVerifier[i] = characters[rand.Intn(len(characters))]
	}
	return base64.RawURLEncoding.EncodeToString(codeVerifier)
}

func GenerateCodeChallenge(codeVerifier string) string {
	verifier := []byte(codeVerifier)
	hashedVerifier := sha256.Sum256(verifier)
	return base64.RawURLEncoding.EncodeToString(hashedVerifier[:])
}
