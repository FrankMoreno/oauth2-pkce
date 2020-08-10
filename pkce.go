package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
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
	ClientID      string
	RedirectURI   string
	AuthEndpoint  string
	TokenEndpoint string
	Scope         string
	verifier      string
	challenge     string
}

// New build an auth struct with given config info.
func New(clientID, redirectURI, authEndpoint, tokenEndpoint, scope string) *Auth {
	return &Auth{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		AuthEndpoint:  authEndpoint,
		TokenEndpoint: tokenEndpoint,
		Scope:         scope,
	}
}

// GenerateCodeVerifier returns a valid code verifier as a string.
func GenerateCodeVerifier(length int, encode bool) (string, error) {
	if length < minVerifierLength || length > maxVerifierLength {
		return "", errInvalidLength
	}

	var codeVerifier = make([]byte, length)

	rand.Seed(time.Now().UTC().UnixNano())

	for i := 0; i < length; i++ {
		codeVerifier[i] = characters[rand.Intn(len(characters))]
	}

	if encode {
		return urlEncode(codeVerifier), nil
	}

	return string(codeVerifier), nil
}

// GenerateCodeChallenge returns a valid code challenge as a string.
func GenerateCodeChallenge(codeVerifier string, encode bool) string {
	verifier := []byte(codeVerifier)
	hashedVerifier := sha256.Sum256(verifier)

	if encode {
		return urlEncode(hashedVerifier[:])
	}

	return string(hashedVerifier[:])
}

// GenerateAuthCodeURL returns the url used to retrieve auth code
func (pa Auth) GenerateAuthCodeURL() string {
	verifier, _ := GenerateCodeVerifier(maxVerifierLength, true)
	challenge := GenerateCodeChallenge(verifier, true)
	pa.verifier = verifier
	pa.challenge = challenge

	return fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&code_challenge_method=S256&code_challenge=%s",
		pa.AuthEndpoint, pa.ClientID, pa.RedirectURI, pa.challenge)
}

// RetrieveToken makes call to the token URL and returns auth token
func (pa Auth) RetrieveToken(code string) (*http.Response, error) {
	data := generateURLData(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     pa.ClientID,
		"code":          code,
		"redirect_uri":  pa.RedirectURI,
		"code_verifier": pa.verifier,
	})

	return http.Post(pa.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data))

	// defer res.Body.Close()
	// body, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	print(err)
	// }
	// fmt.Println(string(body))
}

// RetrieveRefreshedToken takens a refresh token from the previous request and uses it to retrieve a new auth token
func (pa Auth) RetrieveRefreshedToken(refreshToken string) (*http.Response, error) {
	data := generateURLData(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     pa.ClientID,
	})

	return http.Post(pa.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data))
}

func generateURLData(values map[string]string) string {
	urlData := url.Values{}
	for key, value := range values {
		urlData.Set(key, value)
	}
	return urlData.Encode()
}
func urlEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
