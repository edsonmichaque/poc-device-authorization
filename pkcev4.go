package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	token        *oauth2.Token
)

func main() {
	clientID := getEnv("OIDC_CLIENT_ID")
	clientSecret := getEnv("OIDC_CLIENT_SECRET")
	authURL := getEnv("OIDC_AUTH_URL")
	tokenURL := getEnv("OIDC_TOKEN_URL")
	redirectURL := getEnv("OIDC_REDIRECT_URL")

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		RedirectURL: redirectURL,
	}

	// Initial authorization
	err := authorize([]string{"openid", "profile"})
	if err != nil {
		log.Fatalf("Failed to authorize: %v", err)
	}

	// Simulate the need for additional scopes
	time.Sleep(2 * time.Second)
	fmt.Println("Elevating scopes to include 'email'...")

	// Elevate scopes
	err = authorize([]string{"openid", "profile", "email"})
	if err != nil {
		log.Fatalf("Failed to elevate scopes: %v", err)
	}

	fmt.Println("New access token with elevated scopes:", token.AccessToken)
}

func authorize(scopes []string) error {
	oauth2Config.Scopes = scopes

	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	url := oauth2Config.AuthCodeURL(uuid.New().String(), oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	// Open the browser to the URL
	err := browser.OpenURL(url)
	if err != nil {
		return fmt.Errorf("failed to open browser: %v", err)
	}

	// Start the server to handle the callback
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}

		tok, err := oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		token = tok
		fmt.Fprintf(w, "Access Token: %s\n", token.AccessToken)

		// Shutdown the server after receiving the token
		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
	})
	log.Println("Starting server on :17070")
	return http.ListenAndServe(":17070", nil)
}

func generateCodeVerifier() string {
	verifier := uuid.New().String()
	return base64.RawURLEncoding.EncodeToString([]byte(verifier))
}

func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func getEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("Environment variable %s not set", key)
	}
	return value
}
