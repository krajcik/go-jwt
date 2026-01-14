# go-jwt

High-performance JWT library for Go with type-safe custom claims and verification-only mode for microservices.

[![Go Reference](https://pkg.go.dev/badge/github.com/krajcik/go-jwt.svg)](https://pkg.go.dev/github.com/krajcik/go-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/krajcik/go-jwt)](https://goreportcard.com/report/github.com/krajcik/go-jwt)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/krajcik/10af5db30fe4584608dc9053663530b7/raw/coverage.json)](https://github.com/krajcik/go-jwt/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue.svg)](https://golang.org/dl/)
[![Tests](https://github.com/krajcik/go-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/krajcik/go-jwt/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Type-safe custom claims per service
- Asymmetric and HMAC algorithms
- Verification-only mode
- Built-in validation and expiration checks
- Concurrent-safe operations
- Optimized parsing and pooling

## Supported Algorithms

| Algorithm Family | Algorithms | Key Type | Best For |
|-----------------|------------|----------|----------|
| HMAC | HS256, HS384, HS512 | Symmetric (shared secret) | Internal services |
| RSA | RS256, RS384, RS512 | Asymmetric (RSA keys) | Public/private separation |
| ECDSA | ES256, ES384, ES512 | Asymmetric (ECDSA keys) | Efficient asymmetric |
| EdDSA | Ed25519 | Asymmetric (Ed25519 keys) | Modern, fast asymmetric |

## Quick Start

### Sign tokens

```go
package main

import (
  "crypto/rand"
  "crypto/rsa"
  "time"

  "github.com/krajcik/go-jwt"
)

type AuthClaims struct {
  UserID string `json:"user_id"`
}

func main() {
  privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
  algorithm := jwt.NewRS256(privateKey)
  signer, _ := jwt.NewTokenSigner[AuthClaims](algorithm, "auth-service")

  claims := AuthClaims{UserID: "user_123"}
  _, _ = signer.GenerateToken("user_123", time.Hour, claims)
}
```

### Verify tokens

```go
package main

import (
  "crypto/rsa"

  "github.com/krajcik/go-jwt"
)

type ClientClaims struct {
  Permissions []string `json:"permissions"`
}

func main() {
  var publicKey *rsa.PublicKey
  algorithm := jwt.NewRS256WithPublicKey(publicKey)
  verifier, _ := jwt.NewTokenVerifier[ClientClaims](algorithm, "auth-service")

  token := "eyJ..."
  _, _, _ = verifier.VerifyToken(token)
}
```

## Claims Validation

Implement `ClaimsValidator` for automatic validation:

```go
type ClaimsValidator interface {
  Validate() error
}
```

## Error Handling

```go
_, _, err := verifier.VerifyToken(token)
if err != nil {
  switch err {
  case jwt.ErrExpiredToken:
    // token expired
  case jwt.ErrInvalidSignature:
    // invalid signature
  case jwt.ErrInvalidClaims:
    // invalid claims
  default:
    // verification failed
  }
}
```

## Testing

```bash
go test ./... -v
```

## License

MIT. See `LICENSE`.

## Contributing

1. Fork the repo
2. Create a branch
3. Commit changes
4. Push and open a PR
