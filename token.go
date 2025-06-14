package jwt

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/base64x"
	"github.com/goccy/go-json"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrInvalidClaims    = errors.New("invalid claims structure")
	ErrEmptySubject     = errors.New("subject cannot be empty")
	ErrInvalidDuration  = errors.New("duration must be positive")
)

// StandardClaims represents standard JWT claims that are always present
type StandardClaims struct {
	Subject   string `json:"sub,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
	JwtID     string `json:"jti,omitempty"`
}

// ClaimsValidator interface for custom claims validation
type ClaimsValidator interface {
	Validate() error
}

// TokenSigner represents a JWT token signer (Auth Service)
type TokenSigner[T any] struct {
	algorithm Algorithm
	bufPool   sync.Pool
	issuer    string
}

// TokenVerifier represents a JWT token verifier (Client Service)
type TokenVerifier[T any] struct {
	algorithm Algorithm
	bufPool   sync.Pool
	issuer    string
}

// NewTokenSigner creates a new token signer for generating JWTs
func NewTokenSigner[T any](algorithm Algorithm, issuer string) (*TokenSigner[T], error) {
	if algorithm == nil {
		return nil, errors.New("algorithm cannot be nil")
	}

	signer := &TokenSigner[T]{
		algorithm: algorithm,
		issuer:    issuer,
	}

	signer.bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 512)
		},
	}

	return signer, nil
}

// NewTokenVerifier creates a new token verifier for validating JWTs
func NewTokenVerifier[T any](algorithm Algorithm, issuer string) (*TokenVerifier[T], error) {
	if algorithm == nil {
		return nil, errors.New("algorithm cannot be nil")
	}

	verifier := &TokenVerifier[T]{
		algorithm: algorithm,
		issuer:    issuer,
	}

	verifier.bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 512)
		},
	}

	return verifier, nil
}

// GenerateToken creates a new JWT token with custom claims
func (s *TokenSigner[T]) GenerateToken(subject string, duration time.Duration, customClaims T) (string, error) {
	if subject == "" || isWhitespace(subject) {
		return "", errors.New("subject cannot be empty")
	}
	if duration <= 0 {
		return "", errors.New("duration must be positive")
	}

	// Validate custom claims if they implement ClaimsValidator
	if validator, ok := any(customClaims).(ClaimsValidator); ok {
		if err := validator.Validate(); err != nil {
			return "", err
		}
	}

	now := time.Now()

	// Create combined claims structure
	combinedClaims := struct {
		StandardClaims
		Custom T `json:",inline"`
	}{
		StandardClaims: StandardClaims{
			Subject:   subject,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(duration).Unix(),
			Issuer:    s.issuer,
		},
		Custom: customClaims,
	}

	// Get header from algorithm
	headerB64 := s.base64EncodeWithPool(s.algorithm.Header())

	claimsJSON, err := json.Marshal(combinedClaims)
	if err != nil {
		return "", err
	}
	claimsB64 := s.base64EncodeWithPool(claimsJSON)

	var builder strings.Builder
	builder.Grow(len(headerB64) + 1 + len(claimsB64) + 1 + 88)

	builder.WriteString(headerB64)
	builder.WriteByte('.')
	builder.WriteString(claimsB64)

	payload := builder.String()
	signature, err := s.algorithm.Sign([]byte(payload))
	if err != nil {
		return "", err
	}

	builder.WriteByte('.')
	builder.WriteString(s.base64EncodeWithPool(signature))

	return builder.String(), nil
}

// VerifyToken validates a JWT token and returns the claims
func (v *TokenVerifier[T]) VerifyToken(tokenString string) (*StandardClaims, *T, error) {
	payload, claimsPart, signaturePart, err := v.parseTokenParts(tokenString)
	if err != nil {
		return nil, nil, err
	}

	if err := v.verifySignature(payload, signaturePart); err != nil {
		return nil, nil, err
	}

	combinedClaims, err := v.parseClaims(claimsPart)
	if err != nil {
		return nil, nil, err
	}

	if err := v.validateClaims(combinedClaims); err != nil {
		return nil, nil, err
	}

	return &combinedClaims.StandardClaims, &combinedClaims.Custom, nil
}

// parseTokenParts parses JWT token into its components
func (v *TokenVerifier[T]) parseTokenParts(tokenString string) (payload, claimsPart, signaturePart string, err error) {
	firstDot := strings.IndexByte(tokenString, '.')
	if firstDot == -1 {
		return "", "", "", ErrInvalidToken
	}

	secondDot := strings.IndexByte(tokenString[firstDot+1:], '.')
	if secondDot == -1 {
		return "", "", "", ErrInvalidToken
	}
	secondDot += firstDot + 1

	if secondDot <= firstDot || secondDot >= len(tokenString)-1 {
		return "", "", "", ErrInvalidToken
	}

	// Check that there are exactly 3 parts (no more dots after secondDot)
	if strings.IndexByte(tokenString[secondDot+1:], '.') != -1 {
		return "", "", "", ErrInvalidToken
	}

	// Extract parts without allocating new strings until needed
	payload = tokenString[:secondDot]                // header.claims
	claimsPart = tokenString[firstDot+1 : secondDot] // just claims
	signaturePart = tokenString[secondDot+1:]        // signature

	return payload, claimsPart, signaturePart, nil
}

// verifySignature verifies token signature
func (v *TokenVerifier[T]) verifySignature(payload, signaturePart string) error {
	signatureBytes, err := v.base64DecodeWithPool(signaturePart)
	if err != nil {
		return ErrInvalidToken
	}

	if err := v.algorithm.Verify([]byte(payload), signatureBytes); err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// parseClaims parses and decodes JWT claims
func (v *TokenVerifier[T]) parseClaims(claimsPart string) (*struct {
	StandardClaims
	Custom T `json:",inline"`
}, error) {
	claimsData, err := v.base64DecodeWithPool(claimsPart)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var combinedClaims struct {
		StandardClaims
		Custom T `json:",inline"`
	}

	if err := json.Unmarshal(claimsData, &combinedClaims); err != nil {
		return nil, ErrInvalidClaims
	}

	return &combinedClaims, nil
}

// validateClaims validates JWT claims including expiration, issuer, and custom validation
func (v *TokenVerifier[T]) validateClaims(combinedClaims *struct {
	StandardClaims
	Custom T `json:",inline"`
}) error {
	now := time.Now().Unix()

	// Check expiration
	if now > combinedClaims.ExpiresAt {
		return ErrExpiredToken
	}

	// Check not before (if set)
	if combinedClaims.NotBefore > 0 && now < combinedClaims.NotBefore {
		return errors.New("token not yet valid")
	}

	// Check issuer (if set)
	if v.issuer != "" && combinedClaims.Issuer != v.issuer {
		return errors.New("invalid issuer")
	}

	// Validate custom claims if they implement ClaimsValidator
	if validator, ok := any(combinedClaims.Custom).(ClaimsValidator); ok {
		if err := validator.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// base64EncodeWithPool encodes data to base64 using buffer pool
func (s *TokenSigner[T]) base64EncodeWithPool(data []byte) string {
	encodeBuf := s.bufPool.Get().([]byte) //nolint:errcheck // sync.Pool.Get never returns error
	origBuf := encodeBuf
	defer func() {
		s.bufPool.Put(origBuf[:0]) //nolint:staticcheck // slice is converted to interface{} which is correct
	}()

	encodedLen := base64x.RawURLEncoding.EncodedLen(len(data))
	if cap(encodeBuf) < encodedLen {
		encodeBuf = make([]byte, encodedLen)
	}
	encodeBuf = encodeBuf[:encodedLen]

	base64x.RawURLEncoding.Encode(encodeBuf, data)
	return string(encodeBuf)
}

// base64DecodeWithPool decodes base64 string using buffer pool for verifier
func (v *TokenVerifier[T]) base64DecodeWithPool(encoded string) ([]byte, error) {
	decodeBuf := v.bufPool.Get().([]byte) //nolint:errcheck // sync.Pool.Get never returns error
	origBuf := decodeBuf
	defer func() {
		v.bufPool.Put(origBuf[:0]) //nolint:staticcheck // slice is converted to interface{} which is correct
	}()

	decodedLen := base64x.RawURLEncoding.DecodedLen(len(encoded))
	if cap(decodeBuf) < decodedLen {
		decodeBuf = make([]byte, decodedLen)
	}
	decodeBuf = decodeBuf[:decodedLen]

	n, err := base64x.RawURLEncoding.Decode(decodeBuf, []byte(encoded))
	if err != nil {
		return nil, err
	}

	result := make([]byte, n)
	copy(result, decodeBuf[:n])
	return result, nil
}

// isWhitespace checks if string contains only whitespace characters
func isWhitespace(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}
