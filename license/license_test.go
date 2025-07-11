package license

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLicense_Expired(t *testing.T) {
	tests := []struct {
		name      string
		license   *License
		expected  bool
		fixedTime time.Time
	}{
		{
			name:     "zero value never expires",
			license:  &License{},
			expected: false,
		},
		{
			name: "not expired license",
			license: &License{
				ExpiredAt: time.Now().Add(time.Hour).Unix(),
			},
			expected: false,
		},
		{
			name: "expired license",
			license: &License{
				ExpiredAt: time.Now().Add(-time.Hour).Unix(),
			},
			expected: true,
		},
		{
			name: "expires exactly now",
			license: &License{
				ExpiredAt: time.Now().Unix(),
			},
			expected: true,
		},
		{
			name: "negative expiration time",
			license: &License{
				ExpiredAt: -1,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.license.Expired()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestLicense_GetFingerprint(t *testing.T) {
	tests := []struct {
		name         string
		license      *License
		expectedHash string
		wantErr      bool
	}{
		{
			name: "license with ID",
			license: &License{
				ID: "123",
			},
			expectedHash: "ECcsha9GmtgfZtn17D76cO4Kx7kfqeBd2prdVKYGID4",
			wantErr:      false,
		},
		{
			name:         "empty license",
			license:      &License{},
			expectedHash: "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
			wantErr:      false,
		},
		{
			name: "complex license",
			license: &License{
				ID:           "test-id",
				Customer:     "customer-123",
				Subscription: "sub-456",
				Type:         "premium",
				IssuedAt:     1640995200,
				ExpiredAt:    1672531200,
				Data:         []byte(`{"feature":"test"}`),
			},
			expectedHash: "vlw2Q4fXj_6lgcc61cYu0BUH1GEjaRarXuPh-v0O-jw",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := tt.license.GetFingerprint()
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedHash, hash)

			// Verify hash is valid base64
			decoded, err := base64.RawURLEncoding.DecodeString(hash)
			require.NoError(t, err)
			assert.Len(t, decoded, 32) // SHA256 produces 32 bytes

			// Verify hash is deterministic (same input produces same hash)
			hash2, err := tt.license.GetFingerprint()
			require.NoError(t, err)
			assert.Equal(t, hash, hash2)
		})
	}
}
