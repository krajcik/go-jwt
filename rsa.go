package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/goccy/go-json"
)

// RSAAlgorithm implements RSA-based JWT signing
type RSAAlgorithm struct {
	name       string
	hash       crypto.Hash
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	header     []byte
}

// NewRS256 creates a new RSA-SHA256 algorithm instance
func NewRS256(privateKey *rsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	return &RSAAlgorithm{
		name:       "RS256",
		hash:       crypto.SHA256,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewRS384 creates a new RSA-SHA384 algorithm instance
func NewRS384(privateKey *rsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS384", "typ": "JWT"})
	return &RSAAlgorithm{
		name:       "RS384",
		hash:       crypto.SHA384,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewRS512 creates a new RSA-SHA512 algorithm instance
func NewRS512(privateKey *rsa.PrivateKey) Algorithm {
	if privateKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS512", "typ": "JWT"})
	return &RSAAlgorithm{
		name:       "RS512",
		hash:       crypto.SHA512,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		header:     header,
	}
}

// NewRS256WithPublicKey creates a verification-only RS256 instance
func NewRS256WithPublicKey(publicKey *rsa.PublicKey) Algorithm {
	if publicKey == nil {
		return nil
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	return &RSAAlgorithm{
		name:      "RS256",
		hash:      crypto.SHA256,
		publicKey: publicKey,
		header:    header,
	}
}

// Name returns the algorithm name
func (r *RSAAlgorithm) Name() string {
	return r.name
}

// Header returns the algorithm header
func (r *RSAAlgorithm) Header() []byte {
	return r.header
}

// Sign signs the payload using RSA
func (r *RSAAlgorithm) Sign(payload []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, ErrInvalidKeyType
	}

	switch r.hash {
	case crypto.SHA256:
		h := sha256.Sum256(payload)
		return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, h[:])
	case crypto.SHA384:
		h := sha512.Sum384(payload)
		return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA384, h[:])
	case crypto.SHA512:
		h := sha512.Sum512(payload)
		return rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA512, h[:])
	default:
		return nil, ErrInvalidKeyType
	}
}

// Verify verifies the signature using RSA
func (r *RSAAlgorithm) Verify(payload, signature []byte) error {
	if r.publicKey == nil {
		return ErrInvalidKeyType
	}

	switch r.hash {
	case crypto.SHA256:
		h := sha256.Sum256(payload)
		return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, h[:], signature)
	case crypto.SHA384:
		h := sha512.Sum384(payload)
		return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA384, h[:], signature)
	case crypto.SHA512:
		h := sha512.Sum512(payload)
		return rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA512, h[:], signature)
	default:
		return ErrInvalidKeyType
	}
}
