package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLicense_Encode(t *testing.T) {
	t.Run("successful encoding", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID:           "f3a2b3e9-107a-498a-9b5d-24812371ee87",
			Customer:     "fa4dfb36-b26c-4921-95f5-ffa494e688c1",
			Subscription: "31d853e6-d253-4782-adb6-35b85b482c93",
			Type:         "online",
			IssuedAt:     time.Now().Unix(),
			ExpiredAt:    time.Now().Add(time.Hour).Unix(),
			Data:         []byte(`{"test":1}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)
		assert.Contains(t, string(encoded), "-----BEGIN LICENSE KEY-----")
		assert.Contains(t, string(encoded), "-----END LICENSE KEY-----")
	})

	t.Run("encoding with minimal license", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		license := &License{
			ID: "minimal-license",
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)
	})

	t.Run("encoding with complex data", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
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
			ID:        "complex-license",
			IssuedAt:  time.Now().Unix(),
			ExpiredAt: time.Now().Add(24 * time.Hour).Unix(),
			Data:      dataBytes,
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)
	})
}

func TestLicense_Encode_Errors(t *testing.T) {
	tests := []struct {
		name        string
		license     *License
		privateKey  ed25519.PrivateKey
		expectedErr error
	}{
		{
			name:        "nil private key",
			license:     &License{ID: "test"},
			privateKey:  nil,
			expectedErr: ErrPrivateKeyNotDefined,
		},
		{
			name:        "empty license ID",
			license:     &License{},
			privateKey:  nil,
			expectedErr: ErrLicenseIDNotDefined,
		},
		{
			name: "expired before issued",
			license: &License{
				ID:        "test-id",
				IssuedAt:  time.Now().Unix(),
				ExpiredAt: time.Now().Add(-time.Hour).Unix(),
			},
			privateKey:  nil,
			expectedErr: ErrTime,
		},
		{
			name: "expired at same time as issued",
			license: &License{
				ID:        "test-id",
				IssuedAt:  time.Now().Unix(),
				ExpiredAt: time.Now().Unix(),
			},
			privateKey:  nil,
			expectedErr: ErrTime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.license.Encode(tt.privateKey)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestLicense_Encode_Decode_Roundtrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	originalLicense := &License{
		ID:           "f3a2b3e9-107a-498a-9b5d-24812371ee87",
		Customer:     "fa4dfb36-b26c-4921-95f5-ffa494e688c1",
		Subscription: "31d853e6-d253-4782-adb6-35b85b482c93",
		Type:         "online",
		IssuedAt:     time.Now().Unix(),
		ExpiredAt:    time.Now().Add(time.Hour).Unix(),
		Data:         []byte(`{"test":1,"nested":{"value":true}}`),
	}

	encoded, err := originalLicense.Encode(privateKey)
	require.NoError(t, err)

	decoded, err := Decode(encoded, publicKey)
	require.NoError(t, err)

	assert.Equal(t, originalLicense.ID, decoded.ID)
	assert.Equal(t, originalLicense.Customer, decoded.Customer)
	assert.Equal(t, originalLicense.Subscription, decoded.Subscription)
	assert.Equal(t, originalLicense.Type, decoded.Type)
	assert.Equal(t, originalLicense.IssuedAt, decoded.IssuedAt)
	assert.Equal(t, originalLicense.ExpiredAt, decoded.ExpiredAt)
	assert.Equal(t, originalLicense.Data, decoded.Data)
}

func TestLicense_Encode_EmptyFields(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		license *License
	}{
		{
			name: "only ID",
			license: &License{
				ID: "minimal-license",
			},
		},
		{
			name: "ID and customer",
			license: &License{
				ID:       "test-license",
				Customer: "test-customer",
			},
		},
		{
			name: "ID with zero times",
			license: &License{
				ID:        "test-license",
				IssuedAt:  0,
				ExpiredAt: 0,
			},
		},
		{
			name: "ID with nil data",
			license: &License{
				ID:   "test-license",
				Data: nil,
			},
		},
		{
			name: "ID with empty data",
			license: &License{
				ID:   "test-license",
				Data: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.license.Encode(privateKey)
			require.NoError(t, err)
			assert.NotEmpty(t, encoded)
		})
	}
}

func TestLicense_Encode_EdgeCases(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("encode with very large data", func(t *testing.T) {
		// Create valid JSON with large content
		largeJSON := `{"data":"` + strings.Repeat("a", 1024*10) + `"}`

		license := &License{
			ID:   "large-data-license",
			Data: json.RawMessage(largeJSON),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Verify it can be decoded back
		decoded, err := Decode(encoded, privateKey.Public().(ed25519.PublicKey))
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Data, decoded.Data)
	})

	t.Run("encode with special characters in all fields", func(t *testing.T) {
		license := &License{
			ID:           "special-chars-license-测试-🚀",
			Customer:     "customer-with-special-chars-测试-🚀",
			Subscription: "subscription-with-special-chars-测试-🚀",
			Type:         "type-with-special-chars-测试-🚀",
			IssuedAt:     time.Now().Unix(),
			ExpiredAt:    time.Now().Add(time.Hour).Unix(),
			Data:         []byte(`{"special":"chars-测试-🚀","unicode":"👨‍💻"}`),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Verify it can be decoded back
		decoded, err := Decode(encoded, privateKey.Public().(ed25519.PublicKey))
		require.NoError(t, err)
		assert.Equal(t, license.ID, decoded.ID)
		assert.Equal(t, license.Customer, decoded.Customer)
		assert.Equal(t, license.Subscription, decoded.Subscription)
		assert.Equal(t, license.Type, decoded.Type)
		assert.Equal(t, license.Data, decoded.Data)
	})

	t.Run("encode with maximum field lengths", func(t *testing.T) {
		longString := strings.Repeat("a", 1000)
		validJSON := `{"key":"value","long_field":"` + strings.Repeat("x", 500) + `"}`
		license := &License{
			ID:           longString,
			Customer:     longString,
			Subscription: longString,
			Type:         longString,
			IssuedAt:     time.Now().Unix(),
			ExpiredAt:    time.Now().Add(time.Hour).Unix(),
			Data:         json.RawMessage(validJSON),
		}

		encoded, err := license.Encode(privateKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)
	})
}
