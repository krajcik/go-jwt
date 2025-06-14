package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test all HMAC algorithms
func TestAllHMACAlgorithms(t *testing.T) {
	algorithms := map[string]func(string) Algorithm{
		"HS256": NewHS256,
		"HS384": NewHS384,
		"HS512": NewHS512,
	}

	for name, createAlg := range algorithms {
		t.Run(name, func(t *testing.T) {
			// Test valid algorithm creation
			alg := createAlg("test-secret")
			require.NotNil(t, alg)
			assert.Equal(t, name, alg.Name())
			assert.NotEmpty(t, alg.Header())

			// Test signing and verification
			payload := []byte("test.payload")
			signature, err := alg.Sign(payload)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			err = alg.Verify(payload, signature)
			require.NoError(t, err)

			// Test with wrong payload
			err = alg.Verify([]byte("wrong.payload"), signature)
			require.Error(t, err)

			// Test empty secret
			nilAlg := createAlg("")
			assert.Nil(t, nilAlg)
		})
	}
}

// Test all RSA algorithms
func TestAllRSAAlgorithms(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	algorithms := map[string]func(*rsa.PrivateKey) Algorithm{
		"RS256": NewRS256,
		"RS384": NewRS384,
		"RS512": NewRS512,
	}

	publicKeyConstructors := map[string]func(*rsa.PublicKey) Algorithm{
		"RS256": NewRS256WithPublicKey,
	}

	for name, createAlg := range algorithms {
		t.Run(name, func(t *testing.T) {
			// Test valid algorithm creation
			alg := createAlg(privateKey)
			require.NotNil(t, alg)
			assert.Equal(t, name, alg.Name())
			assert.NotEmpty(t, alg.Header())

			// Test signing and verification
			payload := []byte("test.payload")
			signature, err := alg.Sign(payload)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			err = alg.Verify(payload, signature)
			require.NoError(t, err)

			// Test with wrong payload
			err = alg.Verify([]byte("wrong.payload"), signature)
			require.Error(t, err)

			// Test nil key
			nilAlg := createAlg(nil)
			assert.Nil(t, nilAlg)

			// Test public key constructor if available
			if pubKeyConstructor, exists := publicKeyConstructors[name]; exists {
				pubKeyAlg := pubKeyConstructor(&privateKey.PublicKey)
				require.NotNil(t, pubKeyAlg)

				// Should verify but not sign
				err = pubKeyAlg.Verify(payload, signature)
				require.NoError(t, err)

				_, err = pubKeyAlg.Sign(payload)
				require.Error(t, err)

				// Test nil public key
				nilPubAlg := pubKeyConstructor(nil)
				assert.Nil(t, nilPubAlg)
			}
		})
	}
}

// Test all ECDSA algorithms
func TestAllECDSAAlgorithms(t *testing.T) {
	// Generate keys for each curve
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	algorithms := map[string]struct {
		constructor    func(*ecdsa.PrivateKey) Algorithm
		pubConstructor func(*ecdsa.PublicKey) Algorithm
		key            *ecdsa.PrivateKey
	}{
		"ES256": {NewES256, NewES256WithPublicKey, p256Key},
		"ES384": {NewES384, NewES384WithPublicKey, p384Key},
		"ES512": {NewES512, NewES512WithPublicKey, p521Key},
	}

	for name, alg := range algorithms {
		t.Run(name, func(t *testing.T) {
			// Test valid algorithm creation
			signAlg := alg.constructor(alg.key)
			require.NotNil(t, signAlg)
			assert.Equal(t, name, signAlg.Name())
			assert.NotEmpty(t, signAlg.Header())

			// Test signing and verification
			payload := []byte("test.payload")
			signature, err := signAlg.Sign(payload)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			err = signAlg.Verify(payload, signature)
			require.NoError(t, err)

			// Test with wrong payload
			err = signAlg.Verify([]byte("wrong.payload"), signature)
			require.Error(t, err)

			// Test nil private key
			nilAlg := alg.constructor(nil)
			assert.Nil(t, nilAlg)

			// Test public key algorithm
			pubKeyAlg := alg.pubConstructor(&alg.key.PublicKey)
			require.NotNil(t, pubKeyAlg)

			// Should verify but not sign
			err = pubKeyAlg.Verify(payload, signature)
			require.NoError(t, err)

			_, err = pubKeyAlg.Sign(payload)
			require.Error(t, err)

			// Test nil public key
			nilPubAlg := alg.pubConstructor(nil)
			assert.Nil(t, nilPubAlg)
		})
	}
}

// Test EdDSA algorithm edge cases
func TestEdDSAAlgorithmEdgeCases(t *testing.T) {
	publicKey, privateKey, err := GenerateEdDSAKey()
	require.NoError(t, err)

	t.Run("valid EdDSA operations", func(t *testing.T) {
		alg := NewEdDSA(privateKey)
		require.NotNil(t, alg)
		assert.Equal(t, "EdDSA", alg.Name())
		assert.NotEmpty(t, alg.Header())

		payload := []byte("test.payload")
		signature, err := alg.Sign(payload)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)

		err = alg.Verify(payload, signature)
		require.NoError(t, err)
	})

	t.Run("EdDSA with nil private key", func(t *testing.T) {
		alg := NewEdDSA(nil)
		assert.Nil(t, alg)
	})

	t.Run("EdDSA public key verification", func(t *testing.T) {
		signAlg := NewEdDSA(privateKey)
		require.NotNil(t, signAlg)

		payload := []byte("test.payload")
		signature, err := signAlg.Sign(payload)
		require.NoError(t, err)

		// Test verification with public key
		verifyAlg := NewEdDSAWithPublicKey(publicKey)
		require.NotNil(t, verifyAlg)

		err = verifyAlg.Verify(payload, signature)
		require.NoError(t, err)

		// Should not be able to sign
		_, err = verifyAlg.Sign(payload)
		require.Error(t, err)
	})

	t.Run("EdDSA with nil public key", func(t *testing.T) {
		alg := NewEdDSAWithPublicKey(nil)
		assert.Nil(t, alg)
	})

	t.Run("EdDSA verify with wrong key", func(t *testing.T) {
		// Generate different keys
		_, wrongPrivateKey, err := GenerateEdDSAKey()
		require.NoError(t, err)

		signAlg := NewEdDSA(privateKey)
		payload := []byte("test.payload")
		signature, err := signAlg.Sign(payload)
		require.NoError(t, err)

		// Try to verify with wrong key
		wrongVerifyAlg := NewEdDSA(wrongPrivateKey)
		err = wrongVerifyAlg.Verify(payload, signature)
		require.Error(t, err)
	})
}

// Test token validation edge cases
func TestTokenValidationEdgeCases(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	verifier, err := NewTokenVerifier[TestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	customClaims := TestClaims{
		UserID: "user123",
		Role:   "admin",
	}

	t.Run("malformed tokens", func(t *testing.T) {
		testCases := []struct {
			name  string
			token string
		}{
			{"empty token", ""},
			{"no dots", "nodots"},
			{"one dot", "one.dot"},
			{"too many dots", "too.many.dots.here"},
			{"empty parts", ".."},
			{"invalid base64 header", "invalid_base64.valid.valid"},
			{"invalid base64 claims", "valid.invalid_base64.valid"},
			{"invalid base64 signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid_base64"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := verifier.VerifyToken(tc.token)
				require.Error(t, err)
				// Different tokens may fail with different errors
				if tc.name == "invalid base64 signature" {
					assert.Equal(t, ErrInvalidSignature, err)
				} else {
					assert.Equal(t, ErrInvalidToken, err)
				}
			})
		}
	})

	t.Run("invalid JSON in claims", func(t *testing.T) {
		// Create a token with invalid JSON manually
		header := `{"alg":"HS256","typ":"JWT"}`
		invalidClaims := `{"sub":"test","invalid":json}`

		headerB64 := signer.base64EncodeWithPool([]byte(header))
		claimsB64 := signer.base64EncodeWithPool([]byte(invalidClaims))

		payload := headerB64 + "." + claimsB64
		signature, err := algorithm.Sign([]byte(payload))
		require.NoError(t, err)

		token := payload + "." + signer.base64EncodeWithPool(signature)

		_, _, err = verifier.VerifyToken(token)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidClaims, err)
	})

	t.Run("not before time", func(t *testing.T) {
		// Generate token normally - nbf is not currently set in our implementation
		token, err := signer.GenerateToken("user123", time.Hour*2, customClaims)
		require.NoError(t, err)

		// This is a simplified test - in real scenario you'd create token with nbf
		_, _, err = verifier.VerifyToken(token)
		require.NoError(t, err) // Should work as nbf is not set
	})

	t.Run("verify token with buffer pool edge cases", func(t *testing.T) {
		// Test with very large token to test buffer pool expansion
		largeClaims := TestClaims{
			UserID: strings.Repeat("a", 1000),
			Role:   strings.Repeat("b", 1000),
		}

		token, err := signer.GenerateToken("large_user", time.Hour, largeClaims)
		require.NoError(t, err)

		_, _, err = verifier.VerifyToken(token)
		require.NoError(t, err)
	})
}

// Test error paths in algorithms
func TestAlgorithmErrorPaths(t *testing.T) {
	t.Run("RSA sign with public key only", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyAlg := NewRS256WithPublicKey(&privateKey.PublicKey)
		require.NotNil(t, pubKeyAlg)

		_, err = pubKeyAlg.Sign([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key type")
	})

	t.Run("ECDSA sign with public key only", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKeyAlg := NewES256WithPublicKey(&privateKey.PublicKey)
		require.NotNil(t, pubKeyAlg)

		_, err = pubKeyAlg.Sign([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key type")
	})

	t.Run("EdDSA sign with public key only", func(t *testing.T) {
		publicKey, _, err := GenerateEdDSAKey()
		require.NoError(t, err)

		pubKeyAlg := NewEdDSAWithPublicKey(publicKey)
		require.NotNil(t, pubKeyAlg)

		_, err = pubKeyAlg.Sign([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key type")
	})

	t.Run("invalid signature verification", func(t *testing.T) {
		alg := NewHS256("test-secret")
		require.NotNil(t, alg)

		// Test with invalid signature
		err := alg.Verify([]byte("payload"), []byte("invalid-signature"))
		require.Error(t, err)
	})
}

// Test claims for validation testing
type ValidationTestClaims struct {
	Value string `json:"value"`
}

func (c ValidationTestClaims) Validate() error {
	if c.Value == "invalid" {
		return errors.New("value cannot be invalid")
	}
	return nil
}

// Test custom claims validation
func TestCustomClaimsValidation(t *testing.T) {
	algorithm := NewHS256("test-secret")
	signer, err := NewTokenSigner[ValidationTestClaims](algorithm, "test-issuer")
	require.NoError(t, err)

	t.Run("valid custom claims", func(t *testing.T) {
		validClaims := ValidationTestClaims{Value: "valid"}
		token, err := signer.GenerateToken("user", time.Hour, validClaims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("invalid custom claims", func(t *testing.T) {
		invalidClaims := ValidationTestClaims{Value: "invalid"}
		token, err := signer.GenerateToken("user", time.Hour, invalidClaims)
		require.Error(t, err)
		assert.Empty(t, token)
	})
}

// Test constructor edge cases
func TestConstructorEdgeCases(t *testing.T) {
	t.Run("NewTokenSigner with nil algorithm", func(t *testing.T) {
		signer, err := NewTokenSigner[TestClaims](nil, "issuer")
		require.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "algorithm cannot be nil")
	})

	t.Run("NewTokenVerifier with nil algorithm", func(t *testing.T) {
		verifier, err := NewTokenVerifier[TestClaims](nil, "issuer")
		require.Error(t, err)
		assert.Nil(t, verifier)
		assert.Contains(t, err.Error(), "algorithm cannot be nil")
	})
}
