package jwt

import (
	"crypto"
	"errors"
)

var (
	ErrInvalidKeyType = errors.New("invalid key type for algorithm")
)

// Algorithm defines the interface for JWT signing algorithms
type Algorithm interface {
	// Name returns the algorithm name for JWT header (e.g., "HS256", "RS256", "ES256")
	Name() string
	// Sign creates a signature for the given payload
	Sign(payload []byte) ([]byte, error)
	// Verify checks if the signature is valid for the given payload
	Verify(payload []byte, signature []byte) error
	// Header returns the JWT header as JSON bytes
	Header() []byte
}

// Signer represents a key that can sign JWT tokens
type Signer interface {
	crypto.Signer
}

// Verifier represents a key that can verify JWT signatures
type Verifier interface {
	// For HMAC algorithms, this will be the same as Signer
	// For asymmetric algorithms, this will be the public key
	Verify(payload []byte, signature []byte) error
}
