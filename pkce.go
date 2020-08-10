package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
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
	code          string
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

// SetAuthCode adds the auth code to the struct in order to retrieve the token
func (pa Auth) SetAuthCode(code string) {
	pa.code = code
}
func (pa Auth) RetrieveToken() {
	urlData := url.Values{}
	urlData.Set("grant_type", "authorization_code")
	urlData.Set("client_id", pa.ClientID)
	urlData.Set("code", pa.code)
	urlData.Set("redirect_uri", pa.RedirectURI)
	urlData.Set("code_verifier", pa.verifier)

	res, err := http.Post("https://accounts.spotify.com/api/token",
		"application/x-www-form-urlencoded", strings.NewReader(urlData.Encode()))
	if err != nil {
		log.Println(err)
		return
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		print(err)
	}
	fmt.Println(string(body))
}

func urlEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
