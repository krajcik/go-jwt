package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test claims structures
type TestClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (c TestClaims) Validate() error {
	if c.UserID == "" {
		return ErrInvalidClaims
	}
	return nil
}

type InvalidTestClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (c InvalidTestClaims) Validate() error {
	return ErrInvalidClaims
}

// AuthServiceClaims for auth service tests
type AuthServiceClaims struct {
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	TokenType string   `json:"token_type"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
}

// EcommerceClaims for ecommerce service tests
type EcommerceClaims struct {
	CartID       string `json:"cart_id"`
	CustomerTier string `json:"customer_tier"`
	StoreID      string `json:"store_id"`
}

func TestTokenSigner_GenerateToken(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	tests := []struct {
		name         string
		subject      string
		duration     time.Duration
		customClaims TestClaims
		wantErr      bool
	}{
		{
			name:     "valid token generation",
			subject:  "user123",
			duration: time.Hour,
			customClaims: TestClaims{
				UserID: "user123",
				Role:   "admin",
			},
			wantErr: false,
		},
		{
			name:     "empty subject",
			subject:  "",
			duration: time.Hour,
			customClaims: TestClaims{
				UserID: "user123",
				Role:   "admin",
			},
			wantErr: true,
		},
		{
			name:     "whitespace subject",
			subject:  "   ",
			duration: time.Hour,
			customClaims: TestClaims{
				UserID: "user123",
				Role:   "admin",
			},
			wantErr: true,
		},
		{
			name:     "zero duration",
			subject:  "user123",
			duration: 0,
			customClaims: TestClaims{
				UserID: "user123",
				Role:   "admin",
			},
			wantErr: true,
		},
		{
			name:     "negative duration",
			subject:  "user123",
			duration: -time.Hour,
			customClaims: TestClaims{
				UserID: "user123",
				Role:   "admin",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := signer.GenerateToken(tt.subject, tt.duration, tt.customClaims)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)

				// Token should have 3 parts separated by dots
				parts := splitToken(token)
				assert.Len(t, parts, 3)
			}
		})
	}
}

func TestTokenSigner_InvalidCustomClaims(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[InvalidTestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	invalidClaims := InvalidTestClaims{
		UserID: "user123",
		Role:   "admin",
	}

	token, err := signer.GenerateToken("user123", time.Hour, invalidClaims)
	require.Error(t, err)
	assert.Empty(t, token)
	assert.Equal(t, ErrInvalidClaims, err)
}

func TestTokenVerifier_VerifyToken(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	verifier, err := NewTokenVerifier[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	// Generate a valid token
	customClaims := TestClaims{
		UserID: "user123",
		Role:   "admin",
	}
	token, err := signer.GenerateToken("user123", time.Hour, customClaims)
	require.NoError(t, err)

	t.Run("valid token verification", func(t *testing.T) {
		standardClaims, verifiedCustomClaims, err := verifier.VerifyToken(token)
		require.NoError(t, err)

		assert.Equal(t, "user123", standardClaims.Subject)
		assert.Equal(t, "test-issuer", standardClaims.Issuer)
		assert.NotZero(t, standardClaims.IssuedAt)
		assert.NotZero(t, standardClaims.ExpiresAt)

		assert.Equal(t, "user123", verifiedCustomClaims.UserID)
		assert.Equal(t, "admin", verifiedCustomClaims.Role)
	})

	t.Run("invalid token format", func(t *testing.T) {
		_, _, err := verifier.VerifyToken("invalid.token")
		require.Error(t, err)
		assert.Equal(t, ErrInvalidToken, err)
	})

	t.Run("wrong signature", func(t *testing.T) {
		wrongAlgorithm := NewHS256("wrong-secret")
		wrongVerifier, err := NewTokenVerifier[TestClaims](wrongAlgorithm, "test-issuer")
		require.NoError(t, err)

		_, _, err = wrongVerifier.VerifyToken(token)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidSignature, err)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		wrongIssuerVerifier, err := NewTokenVerifier[TestClaims](algorithm, "wrong-issuer")
		require.NoError(t, err)

		_, _, err = wrongIssuerVerifier.VerifyToken(token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer")
	})
}

func TestTokenVerifier_ExpiredToken(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	verifier, err := NewTokenVerifier[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	// Generate a token with short expiry
	customClaims := TestClaims{
		UserID: "user123",
		Role:   "admin",
	}
	token, err := signer.GenerateToken("user123", 1*time.Second, customClaims)
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	_, _, err = verifier.VerifyToken(token)
	require.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestRSATokenGeneration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create signer with private key
	signAlgorithm := NewRS256(privateKey)
	signer, err := NewTokenSigner[TestClaims](signAlgorithm, "rsa-issuer")
	require.NoError(t, err)

	// Create verifier with public key
	verifyAlgorithm := NewRS256WithPublicKey(&privateKey.PublicKey)
	verifier, err := NewTokenVerifier[TestClaims](verifyAlgorithm, "rsa-issuer")
	require.NoError(t, err)

	customClaims := TestClaims{
		UserID: "rsa_user",
		Role:   "user",
	}

	// Generate token with private key
	token, err := signer.GenerateToken("rsa_user", time.Hour, customClaims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token with public key
	standardClaims, verifiedCustomClaims, err := verifier.VerifyToken(token)
	require.NoError(t, err)

	assert.Equal(t, "rsa_user", standardClaims.Subject)
	assert.Equal(t, "rsa-issuer", standardClaims.Issuer)
	assert.Equal(t, "rsa_user", verifiedCustomClaims.UserID)
	assert.Equal(t, "user", verifiedCustomClaims.Role)
}

func TestEdDSATokenGeneration(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := GenerateEdDSAKey()
	require.NoError(t, err)

	// Create signer with private key
	signAlgorithm := NewEdDSA(privateKey)
	signer, err := NewTokenSigner[TestClaims](signAlgorithm, "eddsa-issuer")
	require.NoError(t, err)

	// Create verifier with public key
	verifyAlgorithm := NewEdDSAWithPublicKey(publicKey)
	verifier, err := NewTokenVerifier[TestClaims](verifyAlgorithm, "eddsa-issuer")
	require.NoError(t, err)

	customClaims := TestClaims{
		UserID: "eddsa_user",
		Role:   "admin",
	}

	// Generate token with private key
	token, err := signer.GenerateToken("eddsa_user", time.Hour, customClaims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token with public key
	standardClaims, verifiedCustomClaims, err := verifier.VerifyToken(token)
	require.NoError(t, err)

	assert.Equal(t, "eddsa_user", standardClaims.Subject)
	assert.Equal(t, "eddsa-issuer", standardClaims.Issuer)
	assert.Equal(t, "eddsa_user", verifiedCustomClaims.UserID)
	assert.Equal(t, "admin", verifiedCustomClaims.Role)
}

func TestConcurrentOperations(t *testing.T) {
	algorithm := NewHS256("concurrent-secret")
	signer, err := NewTokenSigner[TestClaims](algorithm, "concurrent-issuer")
	require.NoError(t, err)

	verifier, err := NewTokenVerifier[TestClaims](algorithm, "concurrent-issuer")
	require.NoError(t, err)

	const numGoroutines = 100

	t.Run("concurrent token generation", func(t *testing.T) {
		results := make(chan string, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				customClaims := TestClaims{
					UserID: "concurrent_user",
					Role:   "user",
				}
				token, err := signer.GenerateToken("concurrent_user", time.Hour, customClaims)
				if err != nil {
					errors <- err
					return
				}
				results <- token
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			select {
			case token := <-results:
				assert.NotEmpty(t, token)
			case err := <-errors:
				t.Errorf("Unexpected error: %v", err)
			}
		}
	})

	// Generate a token for verification tests
	customClaims := TestClaims{
		UserID: "verify_user",
		Role:   "user",
	}
	token, err := signer.GenerateToken("verify_user", time.Hour, customClaims)
	require.NoError(t, err)

	t.Run("concurrent token verification", func(t *testing.T) {
		successes := make(chan bool, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				_, _, err := verifier.VerifyToken(token)
				if err != nil {
					errors <- err
					return
				}
				successes <- true
			}()
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			select {
			case success := <-successes:
				assert.True(t, success)
			case err := <-errors:
				t.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func TestDifferentClaimsTypes(t *testing.T) {
	algorithm := NewHS256("multi-claims-secret")

	// Test with AuthServiceClaims
	authSigner, err := NewTokenSigner[AuthServiceClaims](algorithm, "auth-service")
	require.NoError(t, err)

	authVerifier, err := NewTokenVerifier[AuthServiceClaims](algorithm, "auth-service")
	require.NoError(t, err)

	authClaims := AuthServiceClaims{
		UserID:    "auth_user",
		Email:     "user@example.com",
		TokenType: "access",
		Roles:     []string{"user", "admin"},
		Scopes:    []string{"read", "write"},
	}

	authToken, err := authSigner.GenerateToken("auth_user", time.Hour, authClaims)
	require.NoError(t, err)

	_, verifiedAuthClaims, err := authVerifier.VerifyToken(authToken)
	require.NoError(t, err)
	assert.Equal(t, "auth_user", verifiedAuthClaims.UserID)
	assert.Equal(t, "user@example.com", verifiedAuthClaims.Email)
	assert.Contains(t, verifiedAuthClaims.Roles, "admin")

	// Test with EcommerceClaims
	ecommerceSigner, err := NewTokenSigner[EcommerceClaims](algorithm, "ecommerce-service")
	require.NoError(t, err)

	ecommerceVerifier, err := NewTokenVerifier[EcommerceClaims](algorithm, "ecommerce-service")
	require.NoError(t, err)

	ecommerceClaims := EcommerceClaims{
		CartID:       "cart_123",
		CustomerTier: "gold",
		StoreID:      "store_456",
	}

	ecommerceToken, err := ecommerceSigner.GenerateToken("ecommerce_user", time.Hour, ecommerceClaims)
	require.NoError(t, err)

	_, verifiedEcommerceClaims, err := ecommerceVerifier.VerifyToken(ecommerceToken)
	require.NoError(t, err)
	assert.Equal(t, "cart_123", verifiedEcommerceClaims.CartID)
	assert.Equal(t, "gold", verifiedEcommerceClaims.CustomerTier)
}

// Helper function to split token into parts
func splitToken(token string) []string {
	var parts []string
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	if start < len(token) {
		parts = append(parts, token[start:])
	}
	return parts
}
