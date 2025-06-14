package jwt

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/goccy/go-json"
)

// EdDSAAlgorithm implements EdDSA-based JWT signing (Ed25519)
type EdDSAAlgorithm struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	header     []byte
}

// NewEdDSA creates a new EdDSA algorithm instance
func NewEdDSA(privateKey ed25519.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}

	return &EdDSAAlgorithm{
		privateKey: privateKey,
		publicKey:  publicKey,
		header:     header,
	}
}

// NewEdDSAWithPublicKey creates a verification-only EdDSA instance
func NewEdDSAWithPublicKey(publicKey ed25519.PublicKey) Algorithm {
	if publicKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	return &EdDSAAlgorithm{
		publicKey: publicKey,
		header:    header,
	}
}

// GenerateEdDSAKey generates a new Ed25519 key pair
func GenerateEdDSAKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Name returns the algorithm name
func (e *EdDSAAlgorithm) Name() string {
	return "EdDSA"
}

// Header returns the algorithm header
func (e *EdDSAAlgorithm) Header() []byte {
	return e.header
}

// Sign signs the payload using EdDSA
func (e *EdDSAAlgorithm) Sign(payload []byte) ([]byte, error) {
	if e.privateKey == nil {
		return nil, ErrInvalidKeyType
	}

	signature := ed25519.Sign(e.privateKey, payload)
	return signature, nil
}

// Verify verifies the signature using EdDSA
func (e *EdDSAAlgorithm) Verify(payload, signature []byte) error {
	if e.publicKey == nil {
		return ErrInvalidKeyType
	}

	if !ed25519.Verify(e.publicKey, payload, signature) {
		return ErrInvalidSignature
	}

	return nil
}
