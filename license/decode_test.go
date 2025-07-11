package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	t.Run("successful decode with signature verification", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"test":1}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		decoded, err := Decode(encoded, publicKey)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Data, decoded.Data)
	})

	t.Run("successful decode without signature verification", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"test":1}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		decoded, err := Decode(encoded)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Data, decoded.Data)
	})

	t.Run("decode with wrong signature", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"test":1}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		_, err = Decode(encoded, wrongPublicKey)
		assert.ErrorIs(t, err, ErrVerifySignature)
	})

	t.Run("decode with multiple public keys", func(t *testing.T) {
		correctPublicKey, correctPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		wrongPublicKey1, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		wrongPublicKey2, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "test-license",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
		}

		encoded, err := license.Encode(correctPrivateKey)
		require.NoError(t, err)

		decoded, err := Decode(encoded, wrongPublicKey1, wrongPublicKey2, correctPublicKey)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
	})

	t.Run("decode with complex license data", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		complexData := map[string]interface{}{
			"features": []string{"api", "auth", "storage"},
			"limits": map[string]int{
				"users":   1000,
				"storage": 100000,
			},
			"metadata": map[string]string{
				"version": "1.0",
				"region":  "us-east-1",
			},
		}
		dataBytes, err := json.Marshal(complexData)
		require.NoError(t, err)

		license := &License{
			ID:           "complex-license",
			Customer:     "customer-123",
			Subscription: "sub-456",
			Type:         "premium",
			IssuedAt:     time.Now().Unix(),
			ExpiredAt:    time.Now().Add(24 * time.Hour).Unix(),
			Data:         dataBytes,
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		decoded, err := Decode(encoded, publicKey)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Customer, decoded.Customer)
		assert.Equal(t, license.Subscription, decoded.Subscription)
		assert.Equal(t, license.Type, decoded.Type)
		assert.Equal(t, license.Data, decoded.Data)
	})
}

func TestDecode_Errors(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectedErr error
	}{
		{
			name:        "nil data",
			data:        nil,
			expectedErr: ErrMalformedLicense,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectedErr: ErrMalformedLicense,
		},
		{
			name:        "malformed PEM",
			data:        []byte("not a valid PEM"),
			expectedErr: ErrMalformedLicense,
		},
		{
			name:        "wrong PEM type",
			data:        []byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCWxv\n-----END CERTIFICATE-----"),
			expectedErr: ErrMalformedLicense,
		},
		{
			name: "corrupted license data",
			data: func() []byte {
				return pem.EncodeToMemory(&pem.Block{
					Type:  "LICENSE KEY",
					Bytes: []byte("corrupted data"),
				})
			}(),
			expectedErr: nil, // Should fail during decompression
		},
		{
			name: "malformed JSON in license content",
			data: func() []byte {
				compressed, _ := compress([]byte("not valid json"))
				return pem.EncodeToMemory(&pem.Block{
					Type:  "LICENSE KEY",
					Bytes: compressed,
				})
			}(),
			expectedErr: nil, // Should fail during JSON unmarshal
		},
		{
			name: "invalid base64 signature",
			data: func() []byte {
				invalidContent := map[string]string{
					"d": "dGVzdA",             // valid base64
					"s": "invalid base64 !!!", // invalid base64
					"h": "dGVzdA",             // valid base64
				}
				contentBytes, _ := json.Marshal(invalidContent)
				compressed, _ := compress(contentBytes)
				return pem.EncodeToMemory(&pem.Block{
					Type:  "LICENSE KEY",
					Bytes: compressed,
				})
			}(),
			expectedErr: nil, // Should fail during base64 decode
		},
		{
			name: "invalid base64 data hash",
			data: func() []byte {
				invalidContent := map[string]string{
					"d": "dGVzdA",             // valid base64
					"s": "dGVzdA",             // valid base64
					"h": "invalid base64 !!!", // invalid base64
				}
				contentBytes, _ := json.Marshal(invalidContent)
				compressed, _ := compress(contentBytes)
				return pem.EncodeToMemory(&pem.Block{
					Type:  "LICENSE KEY",
					Bytes: compressed,
				})
			}(),
			expectedErr: nil, // Should fail during base64 decode
		},
		{
			name: "invalid base64 encrypted data",
			data: func() []byte {
				invalidContent := map[string]string{
					"d": "invalid base64 !!!", // invalid base64
					"s": "dGVzdA",             // valid base64
					"h": "dGVzdA",             // valid base64
				}
				contentBytes, _ := json.Marshal(invalidContent)
				compressed, _ := compress(contentBytes)
				return pem.EncodeToMemory(&pem.Block{
					Type:  "LICENSE KEY",
					Bytes: compressed,
				})
			}(),
			expectedErr: nil, // Should fail during base64 decode
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.data)
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestDecode_IDMismatch(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	license := &License{
		ID:        "original-id",
		IssuedAt:  time.Now().Unix(),
		ExpiredAt: time.Now().Add(time.Hour).Unix(),
	}

	encoded, err := license.Encode(privateKey)
	require.NoError(t, err)

	// Manually modify the PEM header to have a different ID
	block, _ := pem.Decode(encoded)
	require.NotNil(t, block)
	block.Headers["id"] = "different-id"
	modifiedEncoded := pem.EncodeToMemory(block)

	_, err = Decode(modifiedEncoded)
	assert.ErrorIs(t, err, ErrWrongVerifyID)
}

func TestVerifySignature(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("test message")
		signature := ed25519.Sign(privateKey, message)

		result := verifySignature(message, signature, []ed25519.PublicKey{publicKey})
		assert.True(t, result)
	})

	t.Run("invalid signature", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("test message")
		invalidSignature := make([]byte, ed25519.SignatureSize)

		result := verifySignature(message, invalidSignature, []ed25519.PublicKey{publicKey})
		assert.False(t, result)
	})

	t.Run("no public keys", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, ed25519.SignatureSize)

		result := verifySignature(message, signature, nil)
		assert.False(t, result)

		result = verifySignature(message, signature, []ed25519.PublicKey{})
		assert.False(t, result)
	})

	t.Run("nil public key in slice", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, ed25519.SignatureSize)

		result := verifySignature(message, signature, []ed25519.PublicKey{nil})
		assert.False(t, result)
	})

	t.Run("multiple public keys with one valid", func(t *testing.T) {
		validPublicKey, validPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		invalidPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("test message")
		signature := ed25519.Sign(validPrivateKey, message)

		result := verifySignature(message, signature, []ed25519.PublicKey{
			invalidPublicKey,
			nil,
			validPublicKey,
		})
		assert.True(t, result)
	})

	t.Run("empty message", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		message := []byte("")
		signature := ed25519.Sign(privateKey, message)

		result := verifySignature(message, signature, []ed25519.PublicKey{publicKey})
		assert.True(t, result)
	})
}

func TestDecodeFile(t *testing.T) {
	t.Run("successful file decode", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "file-test-license",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"test":"file"}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		// Create temporary file
		tempFile, err := os.CreateTemp("", "test_license_*.lic")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())

		_, err = tempFile.Write(encoded)
		require.NoError(t, err)
		tempFile.Close()

		// Test decode from file
		decoded, err := DecodeFile(tempFile.Name(), publicKey)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Data, decoded.Data)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := DecodeFile("nonexistent_file.lic")
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("file with invalid content", func(t *testing.T) {
		// Create temporary file with invalid content
		tempFile, err := os.CreateTemp("", "invalid_license_*.lic")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())

		_, err = tempFile.Write([]byte("invalid license content"))
		require.NoError(t, err)
		tempFile.Close()

		_, err = DecodeFile(tempFile.Name())
		assert.ErrorIs(t, err, ErrMalformedLicense)
	})

	t.Run("empty file", func(t *testing.T) {
		// Create empty temporary file
		tempFile, err := os.CreateTemp("", "empty_license_*.lic")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		_, err = DecodeFile(tempFile.Name())
		assert.ErrorIs(t, err, ErrMalformedLicense)
	})

	t.Run("file without signature verification", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "no-verify-license",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		// Create temporary file
		tempFile, err := os.CreateTemp("", "no_verify_license_*.lic")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())

		_, err = tempFile.Write(encoded)
		require.NoError(t, err)
		tempFile.Close()

		// Test decode from file without public key
		decoded, err := DecodeFile(tempFile.Name())
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
	})
}

func TestDecode_ChecksumVerification(t *testing.T) {
	t.Run("checksum verification passes", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "checksum-test",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"checksum":"test"}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		decoded, err := Decode(encoded, publicKey)
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
	})

	t.Run("checksum verification fails", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:        "checksum-test",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(time.Hour).Unix(),
			Data:      []byte(`{"checksum":"test"}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)

		// Manually corrupt the checksum by modifying the license content
		block, _ := pem.Decode(encoded)
		require.NotNil(t, block)

		decompressed, err := decompress(block.Bytes)
		require.NoError(t, err)

		var content licenseContent
		err = json.Unmarshal(decompressed, &content)
		require.NoError(t, err)

		// Corrupt the data hash with valid base64 but wrong hash
		content.DataHash = base64.RawURLEncoding.EncodeToString([]byte("corrupted hash data that is 32 bytes long!"))

		corruptedContent, err := json.Marshal(content)
		require.NoError(t, err)

		corruptedCompressed, err := compress(corruptedContent)
		require.NoError(t, err)

		corruptedEncoded := pem.EncodeToMemory(&pem.Block{
			Type:    "LICENSE KEY",
			Headers: block.Headers,
			Bytes:   corruptedCompressed,
		})

		_, err = Decode(corruptedEncoded, publicKey)
		assert.Error(t, err) // May fail at different points depending on what gets corrupted
	})
}
