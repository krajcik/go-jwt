package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/goccy/go-json"
)

// HMACAlgorithm implements HMAC-based JWT signing
type HMACAlgorithm struct {
	name   string
	hash   func() hash.Hash
	secret []byte
	header []byte
}

// NewHS256 creates a new HMAC-SHA256 algorithm instance
func NewHS256(secret string) Algorithm {
	if secret == "" {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	return &HMACAlgorithm{
		name:   "HS256",
		hash:   sha256.New,
		secret: []byte(secret),
		header: header,
	}
}

// NewHS384 creates a new HMAC-SHA384 algorithm instance
func NewHS384(secret string) Algorithm {
	if secret == "" {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "HS384", "typ": "JWT"})
	return &HMACAlgorithm{
		name:   "HS384",
		hash:   sha512.New384,
		secret: []byte(secret),
		header: header,
	}
}

// NewHS512 creates a new HMAC-SHA512 algorithm instance
func NewHS512(secret string) Algorithm {
	if secret == "" {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "HS512", "typ": "JWT"})
	return &HMACAlgorithm{
		name:   "HS512",
		hash:   sha512.New,
		secret: []byte(secret),
		header: header,
	}
}

// Name returns the algorithm name
func (h *HMACAlgorithm) Name() string {
	return h.name
}

// Header returns the algorithm header
func (h *HMACAlgorithm) Header() []byte {
	return h.header
}

// Sign signs the payload using HMAC
func (h *HMACAlgorithm) Sign(payload []byte) ([]byte, error) {
	mac := hmac.New(h.hash, h.secret)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

// Verify verifies the signature using HMAC
func (h *HMACAlgorithm) Verify(payload, signature []byte) error {
	mac := hmac.New(h.hash, h.secret)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(signature, expected) {
		return ErrInvalidSignature
	}
	return nil
}
