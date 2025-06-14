# JWT Package - Generic Claims Architecture

A high-performance JWT (JSON Web Token) implementation for Go with support for **custom claims types** and **verification-only mode** for microservices architecture.

[![Go Reference](https://pkg.go.dev/badge/github.com/krajcik/go-jwt.svg)](https://pkg.go.dev/github.com/krajcik/go-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/krajcik/go-jwt)](https://goreportcard.com/report/github.com/krajcik/go-jwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Architecture Overview

This JWT package is designed for **microservices architectures** where:

- **Authentication Service** generates tokens (has private key)
- **Client Services** only verify tokens (have public key or use verification endpoint)
- **Each service** can have its own custom claims structure

## ✨ Key Features

- 🔧 **Custom Claims**: Type-safe custom claims for each service
- 🔐 **Asymmetric Algorithms**: RSA, ECDSA, EdDSA support for distributed systems
- 🔑 **Verification-only Mode**: Services can verify without knowing secrets
- 🚀 **High Performance**: Buffer pooling and optimized parsing
- 🛡️ **Security First**: Built-in validation and expiration checking
- 🧵 **Thread Safe**: Concurrent operations supported
- 🎯 **Type Safety**: Generics for compile-time claim validation

## 📦 Supported Algorithms

| Algorithm Family | Algorithms | Key Type | Best For |
|-----------------|------------|----------|----------|
| **HMAC** | HS256, HS384, HS512 | Symmetric (shared secret) | Internal microservices |
| **RSA** | RS256, RS384, RS512 | Asymmetric (RSA keys) | Public/private separation |
| **ECDSA** | ES256, ES384, ES512 | Asymmetric (ECDSA keys) | Efficient asymmetric |
| **EdDSA** | Ed25519 | Asymmetric (Ed25519 keys) | Modern, fast asymmetric |

## 🚀 Quick Start

### 1. Authentication Service (Token Generation)

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "time"
    
    "github.com/krajcik/go-jwt"
)

// Define your custom claims
type AuthClaims struct {
    UserID    string   `json:"user_id"`
    Email     string   `json:"email"`
    Roles     []string `json:"roles"`
    TokenType string   `json:"token_type"`
}

// Implement validation (optional)
func (c AuthClaims) Validate() error {
    if c.UserID == "" {
        return errors.New("user_id is required")
    }
    return nil
}

func main() {
    // Generate RSA key pair for Auth Service
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    
    // Create token signer
    algorithm := jwt.NewRS256(privateKey)
    signer, _ := jwt.NewTokenSigner[AuthClaims](algorithm, "auth-service")
    
    // Generate token with custom claims
    customClaims := AuthClaims{
        UserID:    "user_12345",
        Email:     "user@example.com",
        Roles:     []string{"user", "admin"},
        TokenType: "access",
    }
    
    token, err := signer.GenerateToken("user_12345", time.Hour, customClaims)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Generated token:", token)
}
```

### 2. Client Service (Token Verification)

```go
package main

import (
    "crypto/rsa"
    "fmt"
    
    "github.com/krajcik/go-jwt"
)

// Client service defines its own claims structure
type ClientClaims struct {
    UserID      string `json:"user_id"`
    Permissions []string `json:"permissions"`
}

func main() {
    // Client service only has public key
    var publicKey *rsa.PublicKey // obtained from Auth Service
    
    // Create token verifier (verification-only)
    algorithm := jwt.NewRS256WithPublicKey(publicKey)
    verifier, _ := jwt.NewTokenVerifier[ClientClaims](algorithm, "auth-service")
    
    // Verify token from request
    token := "eyJ..." // from Authorization header
    
    standardClaims, customClaims, err := verifier.VerifyToken(token)
    if err != nil {
        panic(err)
    }
    
    // Use standard claims
    userID := standardClaims.Subject
    expiry := standardClaims.ExpiresAt
    
    // Use custom claims
    permissions := customClaims.Permissions
    
    fmt.Printf("User: %s, Permissions: %v, Expires: %d\n", 
        userID, permissions, expiry)
}
```

## 🏗️ Service-Specific Examples

### E-commerce Service

```go
type EcommerceClaims struct {
    CartID       string `json:"cart_id"`
    CustomerTier string `json:"customer_tier"`
    StoreID      string `json:"store_id"`
}

func (c EcommerceClaims) Validate() error {
    validTiers := map[string]bool{
        "bronze": true, "silver": true, "gold": true, "platinum": true,
    }
    if !validTiers[c.CustomerTier] {
        return errors.New("invalid customer tier")
    }
    return nil
}

// Usage in e-commerce service
algorithm := jwt.NewRS256WithPublicKey(publicKey)
verifier, _ := jwt.NewTokenVerifier[EcommerceClaims](algorithm, "auth-service")

standardClaims, ecommerceClaims, err := verifier.VerifyToken(token)
if err != nil {
    return http.StatusUnauthorized, err
}

// Use e-commerce specific claims
cartID := ecommerceClaims.CartID
customerTier := ecommerceClaims.CustomerTier
```

### Payment Service

```go
type PaymentClaims struct {
    PaymentMethodID string  `json:"payment_method_id"`
    MaxAmount       float64 `json:"max_amount"`
    Currency        string  `json:"currency"`
    MerchantID      string  `json:"merchant_id"`
}

func (c PaymentClaims) Validate() error {
    if c.MaxAmount <= 0 {
        return errors.New("max_amount must be positive")
    }
    return nil
}

// Usage in payment service
algorithm := jwt.NewRS256WithPublicKey(publicKey)
verifier, _ := jwt.NewTokenVerifier[PaymentClaims](algorithm, "auth-service")

_, paymentClaims, err := verifier.VerifyToken(token)
if err != nil {
    return errors.New("invalid payment token")
}

// Validate payment amount against token limits
if requestAmount > paymentClaims.MaxAmount {
    return errors.New("amount exceeds token limit")
}
```

## 🔐 Security Architecture

### Asymmetric Key Distribution

```
┌─────────────────┐    Private Key    ┌─────────────────┐
│  Auth Service   │ ◄─────────────── │   Key Store     │
│ (Token Signing) │                   │                 │
└─────────────────┘                   └─────────────────┘
         │                                      │
         │ Tokens                               │ Public Key
         ▼                                      ▼
┌─────────────────┐                   ┌─────────────────┐
│ Client Service  │ ◄─────────────── │ Client Service  │
│   (Verify)      │    Public Key     │   (Verify)      │
└─────────────────┘                   └─────────────────┘
```

### HMAC Shared Secret (Internal Services)

```go
// For internal microservices that can share secrets
algorithm := jwt.NewHS256("shared-internal-secret")

// Both services can sign and verify
signer, _ := jwt.NewTokenSigner[InternalClaims](algorithm, "internal")
verifier, _ := jwt.NewTokenVerifier[InternalClaims](algorithm, "internal")
```

## 📋 Standard Claims

All tokens include standard JWT claims:

```go
type StandardClaims struct {
    Subject   string `json:"sub"`      // User/entity identifier
    IssuedAt  int64  `json:"iat"`      // Issued at timestamp
    ExpiresAt int64  `json:"exp"`      // Expiration timestamp
    NotBefore int64  `json:"nbf"`      // Not valid before (optional)
    Issuer    string `json:"iss"`      // Token issuer
    Audience  string `json:"aud"`      // Token audience (optional)
    JwtID     string `json:"jti"`      // JWT ID (optional)
}
```

## 🔍 Claims Validation

Implement `ClaimsValidator` interface for automatic validation:

```go
type ClaimsValidator interface {
    Validate() error
}

type UserClaims struct {
    UserID string `json:"user_id"`
    Email  string `json:"email"`
}

func (c UserClaims) Validate() error {
    if c.UserID == "" {
        return errors.New("user_id cannot be empty")
    }
    
    emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
    if c.Email != "" && !emailRegex.MatchString(c.Email) {
        return errors.New("invalid email format")
    }
    
    return nil
}
```

## ❌ Error Handling

```go
standardClaims, customClaims, err := verifier.VerifyToken(token)
if err != nil {
    switch err {
    case jwt.ErrExpiredToken:
        return http.StatusUnauthorized, "Token expired"
    case jwt.ErrInvalidSignature:
        return http.StatusUnauthorized, "Invalid token"
    case jwt.ErrInvalidClaims:
        return http.StatusBadRequest, "Invalid claims"
    default:
        return http.StatusInternalServerError, "Token verification failed"
    }
}
```

## 🚀 Performance Features

- **Buffer Pooling**: Reduces memory allocations
- **Manual Token Parsing**: 5.6x faster than `strings.Split`
- **High-Performance Libraries**: `goccy/go-json` and `cloudwego/base64x`
- **Zero-Copy Operations**: Optimized string handling
- **Concurrent Safe**: Thread-safe operations

## 🧪 Testing

```bash
# Run all tests
go test ./... -v

# Run tests with coverage
go test ./... -cover

# Run specific test
go test ./... -run TestTokenSigner -v
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- Optimized with high-performance libraries: `goccy/go-json` and `cloudwego/base64x`
- Designed for modern microservices architectures
- Built for production use in distributed systems