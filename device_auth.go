package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

type OIDCConfig struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Expiry       time.Time
}

const (
	tokenFilePath  = "./token.json"
	serviceName    = "myapp"
	keyringAccount = "token-encryption-key"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "device-auth",
	}

	rootCmd.AddCommand(authCmd())
	rootCmd.AddCommand(exportEnvCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func authCmd() *cobra.Command {
	return &cobra.Command{
		Use: "auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := getEnv("KEYCLOAK_CLIENT_ID")
			clientSecret := getEnv("KEYCLOAK_CLIENT_SECRET")
			oidcConfigEndpoint := getEnv("OIDC_CONFIG_ENDPOINT")

			config, err := fetchOIDCConfig(oidcConfigEndpoint)
			if err != nil {
				return err
			}

			token, err := loadTokenFromFile()
			if err == nil && !isTokenExpired(token) {
				fmt.Println("Using cached access token:", token.AccessToken)
				return nil
			}

			if token != nil && token.RefreshToken != "" {
				refreshedToken, err := refreshToken(clientID, clientSecret, config.TokenEndpoint, token.RefreshToken)
				if err == nil {
					saveTokenToFile(refreshedToken)
					fmt.Println("Refreshed access token:", refreshedToken.AccessToken)
					return nil
				}
				log.Println("Failed to refresh token:", err)
			}

			deviceCode, userCode, verificationURI, err := getDeviceCode(clientID, clientSecret, config.DeviceAuthorizationEndpoint)
			if err != nil {
				return err
			}

			fmt.Println("Please visit", verificationURI, "and enter the code:", userCode)

			token, err = pollForToken(clientID, clientSecret, deviceCode, config.TokenEndpoint)
			if err != nil {
				return err
			}

			saveTokenToFile(token)
			fmt.Println("Access token:", token.AccessToken)
			return nil
		},
	}
}

func exportEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-env",
		Short: "Generate shell commands to export environment variables",
		Run: func(cmd *cobra.Command, args []string) {
			clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
			clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
			oidcConfigEndpoint := os.Getenv("OIDC_CONFIG_ENDPOINT")

			fmt.Printf("export KEYCLOAK_CLIENT_ID=%s\n", clientID)
			fmt.Printf("export KEYCLOAK_CLIENT_SECRET=%s\n", clientSecret)
			fmt.Printf("export OIDC_CONFIG_ENDPOINT=%s\n", oidcConfigEndpoint)
		},
	}
}

func getEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("Environment variable %s not set", key)
	}
	return value
}

func fetchOIDCConfig(configEndpoint string) (*OIDCConfig, error) {
	resp, err := http.Get(configEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %v", err)
	}
	defer resp.Body.Close()

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC configuration: %v", err)
	}

	return &config, nil
}

func getDeviceCode(clientID, clientSecret, deviceAuthEndpoint string) (string, string, string, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "openid profile")

	resp, err := http.PostForm(deviceAuthEndpoint, data)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	deviceCode, ok := result["device_code"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("failed to get device code: %v", result)
	}

	userCode, ok := result["user_code"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("failed to get user code: %v", result)
	}

	verificationURI, ok := result["verification_uri"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("failed to get verification URI: %v", result)
	}

	return deviceCode, userCode, verificationURI, nil
}

func pollForToken(clientID, clientSecret, deviceCode, tokenEndpoint string) (*TokenResponse, error) {
	for {
		data := url.Values{}
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		data.Set("device_code", deviceCode)
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		resp, err := http.PostForm(tokenEndpoint, data)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)

		var result map[string]interface{}
		json.Unmarshal(body, &result)

		if accessToken, ok := result["access_token"].(string); ok {
			expiresIn := int(result["expires_in"].(float64))
			refreshToken := result["refresh_token"].(string)
			tokenType := result["token_type"].(string)

			return &TokenResponse{
				AccessToken:  accessToken,
				ExpiresIn:    expiresIn,
				RefreshToken: refreshToken,
				TokenType:    tokenType,
				Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
			}, nil
		}

		if err, ok := result["error"].(string); ok {
			if err == "authorization_pending" {
				time.Sleep(5 * time.Second)
				continue
			}
			return nil, fmt.Errorf("error: %s", err)
		}
	}
}

func refreshToken(clientID, clientSecret, tokenEndpoint, refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(body, &result)

	if accessToken, ok := result["access_token"].(string); ok {
		expiresIn := int(result["expires_in"].(float64))
		refreshToken := result["refresh_token"].(string)
		tokenType := result["token_type"].(string)

		return &TokenResponse{
			AccessToken:  accessToken,
			ExpiresIn:    expiresIn,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
		}, nil
	}

	if err, ok := result["error"].(string); ok {
		return nil, fmt.Errorf("failed to refresh token: %s", err)
	}

	return nil, fmt.Errorf("unexpected response: %v", result)
}

func isTokenExpired(token *TokenResponse) bool {
	return time.Now().After(token.Expiry)
}

func saveTokenToFile(token *TokenResponse) error {
	// Encrypt the token before saving
	encryptedToken, err := encryptToken(token)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(tokenFilePath, encryptedToken, 0600)
}

func loadTokenFromFile() (*TokenResponse, error) {
	if _, err := os.Stat(tokenFilePath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := ioutil.ReadFile(tokenFilePath)
	if err != nil {
		return nil, err
	}

	return decryptToken(data)
}

func getEncryptionKey() ([]byte, error) {
	// Get the encryption key from the keyring
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

func encryptToken(token *TokenResponse) ([]byte, error) {
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

func decryptToken(ciphertext []byte) (*TokenResponse, error) {
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

	var token TokenResponse
	if err := json.Unmarshal(ciphertext, &token); err != nil {
		return nil, err
	}

	return &token, nil
}
