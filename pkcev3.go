package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

var (
	oauth2Config   *oauth2.Config
	codeVerifier   string
	serviceName    = "myapp"
	keyringAccount = "pkce-encryption-key"
	tokenFilePath  = "pkce-token.json"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "authctl",
	}

	rootCmd.AddCommand(authCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func authCmd() *cobra.Command {
	return &cobra.Command{
		Use: "auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := getEnv("OIDC_CLIENT_ID")
			clientSecret := getEnv("OIDC_CLIENT_SECRET")
			authURL := getEnv("OIDC_AUTH_URL")
			tokenURL := getEnv("OIDC_TOKEN_URL")
			redirectURL := getEnv("OIDC_REDIRECT_URL")

			oauth2Config = &oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  authURL,
					TokenURL: tokenURL,
				},
				RedirectURL: redirectURL,
			}

			// Check if the token file exists
			token, err := loadTokenFromFile()
			if err == nil {
				if token.Expiry.After(time.Now()) {
					fmt.Println("Using cached access token:", token.AccessToken)
					return nil
				} else {
					fmt.Println("Access token expired, refreshing...")
					token, err = refreshToken(token)
					if err == nil {
						saveTokenToFile(token)
						fmt.Println("Refreshed access token:", token.AccessToken)
						return nil
					}
				}
			}

			codeVerifier = generateCodeVerifier()
			codeChallenge := generateCodeChallenge(codeVerifier)

			url := oauth2Config.AuthCodeURL(uuid.New().String(), oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

			// Open the browser to the URL
			openBrowser(url)

			// Start the server to handle the callback
			http.HandleFunc("/callback", handleCallback)
			log.Println("Starting server on :17070")
			return http.ListenAndServe(":17070", nil)
		},
	}
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	saveTokenToFile(token)
	fmt.Fprintf(w, "Access Token: %s\n", token.AccessToken)

	// Shutdown the server after receiving the token
	go func() {
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}

func getEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("Environment variable %s not set", key)
	}
	return value
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

func openBrowser(url string) {
	var err error

	switch os := runtime.GOOS; os {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatalf("Failed to open browser: %v", err)
	}
}

func saveTokenToFile(token *oauth2.Token) error {
	encryptedToken, err := encryptToken(token)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(tokenFilePath, encryptedToken, 0600)
}

func loadTokenFromFile() (*oauth2.Token, error) {
	if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := ioutil.ReadFile(tokenFilePath)
	if err != nil {
		return nil, err
	}

	return decryptToken(data)
}

func encryptToken(token *oauth2.Token) ([]byte, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decryptToken(ciphertext []byte) (*oauth2.Token, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	var token oauth2.Token
	if err := json.Unmarshal(ciphertext, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func getEncryptionKey() ([]byte, error) {
	key, err := keyring.Get(serviceName, keyringAccount)
	if err == keyring.ErrNotFound {
		// If the key doesn't exist, generate a new one
		newKey := make([]byte, 32)
		if _, err := rand.Read(newKey); err != nil {
			return nil, err
		}

		// Store the new key in the keyring
		err = keyring.Set(serviceName, keyringAccount, base64.StdEncoding.EncodeToString(newKey))
		if err != nil {
			return nil, err
		}

		return newKey, nil
	} else if err != nil {
		return nil, err
	}

	// Decode the base64 encoded key
	return base64.StdEncoding.DecodeString(key)
}

func refreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	ctx := context.Background()
	ts := oauth2Config.TokenSource(ctx, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}
