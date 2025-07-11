# Go License

[![codecov](https://codecov.io/github/vitalvas/go-license/graph/badge.svg?token=2NZ71AW15P)](https://codecov.io/github/vitalvas/go-license)
[![Go Report Card](https://goreportcard.com/badge/github.com/vitalvas/go-license)](https://goreportcard.com/report/github.com/vitalvas/go-license)
[![GoDoc](https://godoc.org/github.com/vitalvas/go-license?status.svg)](https://godoc.org/github.com/vitalvas/go-license)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A robust and secure Go library for generating, encoding, and validating software licenses with cryptographic signatures.

## Features

- **Cryptographic Security**: Uses Ed25519 digital signatures for license verification
- **Data Encryption**: ChaCha20-Poly1305 AEAD encryption for license content
- **Compression**: Built-in data compression to minimize license size
- **Flexible Metadata**: Support for custom JSON data in licenses
- **Expiration Handling**: Automatic license expiration validation
- **PEM Format**: Human-readable PEM encoding for license distribution
- **High Performance**: Optimized for speed and memory efficiency

## Installation

```bash
go get github.com/vitalvas/go-license
```

## Quick Start

### Generating a License

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "log"
    "time"

    "github.com/vitalvas/go-license/license"
)

func main() {
    // Generate Ed25519 key pair
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // Create license with custom data
    customData := map[string]interface{}{
        "features": []string{"api", "auth", "storage"},
        "limits": map[string]int{
            "users": 100,
            "storage": 10000,
        },
    }
    dataBytes, _ := json.Marshal(customData)

    lic := &license.License{
        ID:           "license-001",
        Customer:     "customer-123",
        Subscription: "sub-456",
        Type:         "premium",
        IssuedAt:     time.Now().Unix(),
        ExpiredAt:    time.Now().Add(365 * 24 * time.Hour).Unix(),
        Data:         dataBytes,
    }

    // Encode license
    encoded, err := lic.Encode(privateKey)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("License Key:\n%s\n", encoded)
}
```

### Validating a License

```go
// Decode and validate license
decoded, err := license.Decode(encoded, publicKey)
if err != nil {
    log.Fatal(err)
}

// Check if license is expired
if decoded.Expired() {
    log.Fatal("License has expired")
}

// Access license data
fmt.Printf("License ID: %s\n", decoded.ID)
fmt.Printf("Customer: %s\n", decoded.Customer)
fmt.Printf("Expires: %s\n", time.Unix(decoded.ExpiredAt, 0))
```

## License Key Format

The license key uses a structured format with multiple layers of security:

### 1. Overall Structure

```
-----BEGIN LICENSE KEY-----
id: license-001
<base64-encoded-compressed-data>
-----END LICENSE KEY-----
```

### 2. License Data Structure

```go
type License struct {
    ID           string          `json:"id,omitempty"`  // Unique license identifier
    Customer     string          `json:"cus,omitempty"` // Customer identifier
    Subscription string          `json:"sub,omitempty"` // Subscription identifier
    Type         string          `json:"typ,omitempty"` // License type (e.g., "premium", "online", "offline", etc.)
    IssuedAt     int64           `json:"iat,omitempty"` // Issue timestamp (Unix)
    ExpiredAt    int64           `json:"exp,omitempty"` // Expiration timestamp (Unix)
    Data         json.RawMessage `json:"dat,omitempty"` // Custom metadata (JSON)
}
```

## Command Line Tools

### License Inspector

The `licensecat` command-line tool allows you to inspect license files:

```bash
# Build the tool
go build -o licensecat ./cmd/licensecat

# Inspect a license file
./licensecat -file license.key
```

Output:
```
License ID: license-001
License Customer: customer-123
License Subscription: sub-456
License Type: premium
License Issued At: 1640995200 (2022-01-01 00:00:00 +0000)
License Expires At: 1672531200 (2023-01-01 00:00:00 +0000)
License Data:
{
  "features": ["api", "auth", "storage"],
  "limits": {
    "users": 100,
    "storage": 10000
  }
}
```

## Examples

### Custom License Data

```go
// Define custom license data structure
type LicenseData struct {
    Organization string            `json:"org"`
    Features     []string          `json:"features"`
    Limits       map[string]int    `json:"limits"`
    Metadata     map[string]string `json:"metadata"`
}

// Create license with custom data
customData := LicenseData{
    Organization: "ACME Corp",
    Features:     []string{"api", "auth.google", "auth.ldap"},
    Limits: map[string]int{
        "users":   1000,
        "storage": 100000,
    },
    Metadata: map[string]string{
        "version": "1.0",
        "region":  "us-east-1",
    },
}

dataBytes, _ := json.Marshal(customData)
license := &license.License{
    ID:   "custom-license",
    Data: dataBytes,
}
```

### License Validation with Custom Logic

```go
func validateLicense(licenseData []byte, publicKey ed25519.PublicKey) error {
    // Decode license
    lic, err := license.Decode(licenseData, publicKey)
    if err != nil {
        return fmt.Errorf("failed to decode license: %w", err)
    }

    // Check expiration
    if lic.Expired() {
        return fmt.Errorf("license expired on %s", 
            time.Unix(lic.ExpiredAt, 0).Format("2006-01-02"))
    }

    // Validate custom data
    var customData LicenseData
    if err := json.Unmarshal(lic.Data, &customData); err != nil {
        return fmt.Errorf("invalid license data: %w", err)
    }

    // Check if required features are enabled
    if !strings.Contains(customData.Features, "api") {
        return fmt.Errorf("API feature not enabled in license")
    }

    return nil
}

```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and versions.

## Support

For questions and support:

- Open an issue on GitHub
- Check the [examples](examples/) directory for usage examples
- Review the [API documentation](https://godoc.org/github.com/vitalvas/go-license)
