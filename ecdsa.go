package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"github.com/goccy/go-json"
)

// ECDSAAlgorithm implements ECDSA-based JWT signing
type ECDSAAlgorithm struct {
	name       string
	curve      elliptic.Curve
	keySize    int
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	header     []byte
}

// NewES256 creates a new ECDSA-SHA256 algorithm instance (P-256 curve)
func NewES256(privateKey *ecdsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:       "ES256",
		curve:      elliptic.P256(),
		keySize:    32,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewES384 creates a new ECDSA-SHA384 algorithm instance (P-384 curve)
func NewES384(privateKey *ecdsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES384", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:       "ES384",
		curve:      elliptic.P384(),
		keySize:    48,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewES512 creates a new ECDSA-SHA512 algorithm instance (P-521 curve)
func NewES512(privateKey *ecdsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES512", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:       "ES512",
		curve:      elliptic.P521(),
		keySize:    66,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewES256WithPublicKey creates a verification-only ES256 instance
func NewES256WithPublicKey(publicKey *ecdsa.PublicKey) Algorithm {
	if publicKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:      "ES256",
		curve:     elliptic.P256(),
		keySize:   32,
		publicKey: publicKey,
		header:    header,
	}
}

// NewES384WithPublicKey creates a verification-only ES384 instance
func NewES384WithPublicKey(publicKey *ecdsa.PublicKey) Algorithm {
	if publicKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES384", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:      "ES384",
		curve:     elliptic.P384(),
		keySize:   48,
		publicKey: publicKey,
		header:    header,
	}
}

// NewES512WithPublicKey creates a verification-only ES512 instance
func NewES512WithPublicKey(publicKey *ecdsa.PublicKey) Algorithm {
	if publicKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "ES512", "typ": "JWT"})
	return &ECDSAAlgorithm{
		name:      "ES512",
		curve:     elliptic.P521(),
		keySize:   66,
		publicKey: publicKey,
		header:    header,
	}
}

// Name returns the algorithm name
func (e *ECDSAAlgorithm) Name() string {
	return e.name
}

// Header returns the algorithm header
func (e *ECDSAAlgorithm) Header() []byte {
	return e.header
}

// Sign signs the payload using ECDSA
func (e *ECDSAAlgorithm) Sign(payload []byte) ([]byte, error) {
	if e.privateKey == nil {
		return nil, ErrInvalidKeyType
	}

	var hash []byte
	switch e.name {
	case "ES256":
		h := sha256.Sum256(payload)
		hash = h[:]
	case "ES384":
		h := sha512.Sum384(payload)
		hash = h[:]
	case "ES512":
		h := sha512.Sum512(payload)
		hash = h[:]
	default:
		return nil, ErrInvalidKeyType
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hash)
	if err != nil {
		return nil, err
	}

	// Convert to fixed-length byte representation
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	signature := make([]byte, 2*e.keySize)
	copy(signature[e.keySize-len(rBytes):e.keySize], rBytes)
	copy(signature[2*e.keySize-len(sBytes):], sBytes)

	return signature, nil
}

// Verify verifies the signature using ECDSA
func (e *ECDSAAlgorithm) Verify(payload, signature []byte) error {
	if e.publicKey == nil {
		return ErrInvalidKeyType
	}

	if len(signature) != 2*e.keySize {
		return ErrInvalidSignature
	}

	var hash []byte
	switch e.name {
	case "ES256":
		h := sha256.Sum256(payload)
		hash = h[:]
	case "ES384":
		h := sha512.Sum384(payload)
		hash = h[:]
	case "ES512":
		h := sha512.Sum512(payload)
		hash = h[:]
	default:
		return ErrInvalidKeyType
	}

	r := new(big.Int).SetBytes(signature[:e.keySize])
	s := new(big.Int).SetBytes(signature[e.keySize:])

	if !ecdsa.Verify(e.publicKey, hash, r, s) {
		return ErrInvalidSignature
	}

	return nil
}
