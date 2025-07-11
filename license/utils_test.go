package license

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCompress(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: []byte{0x1, 0x0, 0x0, 0xff, 0xff},
			wantErr:  false,
		},
		{
			name:  "small string",
			input: []byte("hello"),
			expected: []byte{
				0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x7, 0x4, 0x0, 0x0, 0xff, 0xff,
			},
			wantErr: false,
		},
		{
			name:    "repeated pattern",
			input:   []byte("aaaaaaaaaaaaaaaa"),
			wantErr: false,
		},
		{
			name:    "json data",
			input:   []byte(`{"key":"value","number":123}`),
			wantErr: false,
		},
		{
			name:    "large data",
			input:   make([]byte, 10000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := compress(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			if tt.expected != nil {
				assert.Equal(t, tt.expected, result)
			}

			// Verify compression worked by decompressing
			decompressed, err := decompress(result)
			require.NoError(t, err)
			assert.Equal(t, tt.input, decompressed)

			// Verify compression ratio for large data
			if len(tt.input) > 1000 {
				compressionRatio := float64(len(result)) / float64(len(tt.input))
				assert.Less(t, compressionRatio, 1.0, "compression should reduce size")
			}
		})
	}
}

func TestDecompress(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty compressed data",
			input:    []byte{0x1, 0x0, 0x0, 0xff, 0xff},
			expected: []byte{},
			wantErr:  false,
		},
		{
			name: "small string",
			input: []byte{
				0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x7, 0x4, 0x0, 0x0, 0xff, 0xff,
			},
			expected: []byte("hello"),
			wantErr:  false,
		},
		{
			name:     "invalid compressed data",
			input:    []byte{0x0, 0x1, 0x2, 0x3},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "truncated compressed data",
			input:    []byte{0x1, 0x0},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty input",
			input:    []byte{},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decompress(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompress_Decompress_Roundtrip(t *testing.T) {
	testCases := [][]byte{
		{},
		[]byte("hello world"),
		[]byte("{}"),
		[]byte(`{"complex":"json","with":["arrays",123,true]}`),
		bytes.Repeat([]byte("repeat"), 100),
		make([]byte, 1000), // Zero bytes
	}

	// Fill the zero bytes with some pattern
	for i := range testCases[len(testCases)-1] {
		testCases[len(testCases)-1][i] = byte(i % 256)
	}

	for i, data := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			compressed, err := compress(data)
			require.NoError(t, err)

			decompressed, err := decompress(compressed)
			require.NoError(t, err)

			assert.Equal(t, data, decompressed)
		})
	}
}

func TestEncryptData(t *testing.T) {
	validKey := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(validKey)
	require.NoError(t, err)

	validNonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(validNonce)
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		key     []byte
		nonce   []byte
		wantErr bool
	}{
		{
			name:    "valid encryption",
			data:    []byte("test data"),
			key:     validKey,
			nonce:   validNonce,
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			key:     validKey,
			nonce:   validNonce,
			wantErr: false,
		},
		{
			name:    "large data",
			data:    make([]byte, 10000),
			key:     validKey,
			nonce:   validNonce,
			wantErr: false,
		},
		{
			name:    "key too short",
			data:    []byte("test"),
			key:     []byte("short"),
			nonce:   validNonce,
			wantErr: true,
		},
		{
			name:    "key exact size",
			data:    []byte("test"),
			key:     make([]byte, chacha20poly1305.KeySize),
			nonce:   validNonce,
			wantErr: false,
		},
		{
			name:    "key too long (should work)",
			data:    []byte("test"),
			key:     make([]byte, chacha20poly1305.KeySize+10),
			nonce:   validNonce,
			wantErr: false,
		},
		{
			name:    "nonce too short",
			data:    []byte("test"),
			key:     validKey,
			nonce:   []byte("short"),
			wantErr: true,
		},
		{
			name:    "nonce exact size",
			data:    []byte("test"),
			key:     validKey,
			nonce:   make([]byte, chacha20poly1305.NonceSize),
			wantErr: false,
		},
		{
			name:    "nonce too long (should work)",
			data:    []byte("test"),
			key:     validKey,
			nonce:   make([]byte, chacha20poly1305.NonceSize+10),
			wantErr: false,
		},
		{
			name:    "nil key",
			data:    []byte("test"),
			key:     nil,
			nonce:   validNonce,
			wantErr: true,
		},
		{
			name:    "nil nonce",
			data:    []byte("test"),
			key:     validKey,
			nonce:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encryptData(tt.data, tt.key, tt.nonce)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotEqual(t, tt.data, result)          // Encrypted data should be different
			assert.Greater(t, len(result), len(tt.data)) // Encrypted data should be longer due to auth tag
		})
	}
}

func TestDecryptData(t *testing.T) {
	validKey := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(validKey)
	require.NoError(t, err)

	validNonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(validNonce)
	require.NoError(t, err)

	// Create valid encrypted data
	testData := []byte("test data for decryption")
	validEncrypted, err := encryptData(testData, validKey, validNonce)
	require.NoError(t, err)

	tests := []struct {
		name     string
		data     []byte
		key      []byte
		nonce    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "valid decryption",
			data:     validEncrypted,
			key:      validKey,
			nonce:    validNonce,
			expected: testData,
			wantErr:  false,
		},
		{
			name:     "empty encrypted data",
			data:     func() []byte { e, _ := encryptData([]byte{}, validKey, validNonce); return e }(),
			key:      validKey,
			nonce:    validNonce,
			expected: nil,
			wantErr:  false,
		},
		{
			name:     "wrong key",
			data:     validEncrypted,
			key:      make([]byte, chacha20poly1305.KeySize),
			nonce:    validNonce,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "wrong nonce",
			data:     validEncrypted,
			key:      validKey,
			nonce:    make([]byte, chacha20poly1305.NonceSize),
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "key too short",
			data:     validEncrypted,
			key:      []byte("short"),
			nonce:    validNonce,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "nonce too short",
			data:     validEncrypted,
			key:      validKey,
			nonce:    []byte("short"),
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "corrupted encrypted data",
			data:     []byte("corrupted data"),
			key:      validKey,
			nonce:    validNonce,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "nil encrypted data",
			data:     nil,
			key:      validKey,
			nonce:    validNonce,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "nil key",
			data:     validEncrypted,
			key:      nil,
			nonce:    validNonce,
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "nil nonce",
			data:     validEncrypted,
			key:      validKey,
			nonce:    nil,
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decryptData(tt.data, tt.key, tt.nonce)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestEncryptData_DecryptData_Roundtrip(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	testCases := [][]byte{
		nil,
		[]byte("hello"),
		[]byte("{}"),
		[]byte(`{"complex":"json","with":["arrays",123,true]}`),
		bytes.Repeat([]byte("test"), 1000),
		make([]byte, 10000),
	}

	// Fill the large byte array with random data
	_, err = rand.Read(testCases[len(testCases)-1])
	require.NoError(t, err)

	for i, data := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			encrypted, err := encryptData(data, key, nonce)
			require.NoError(t, err)

			decrypted, err := decryptData(encrypted, key, nonce)
			require.NoError(t, err)

			if data == nil {
				assert.Nil(t, decrypted)
			} else {
				assert.Equal(t, data, decrypted)
			}
		})
	}
}

func TestEncryptData_DecryptData_DifferentKeys(t *testing.T) {
	key1 := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key1)
	require.NoError(t, err)

	key2 := make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	data := []byte("secret data")

	// Encrypt with key1
	encrypted, err := encryptData(data, key1, nonce)
	require.NoError(t, err)

	// Try to decrypt with key2 (should fail)
	_, err = decryptData(encrypted, key2, nonce)
	require.Error(t, err)

	// Decrypt with correct key1 (should succeed)
	decrypted, err := decryptData(encrypted, key1, nonce)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestUtils_EdgeCases(t *testing.T) {
	t.Run("compress writer error simulation", func(t *testing.T) {
		// This test would require mocking the writer to simulate errors
		// For now, we test with valid data since the current implementation
		// doesn't have easily mockable error conditions
		data := []byte("test data")
		result, err := compress(data)
		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("decompress reader error simulation", func(t *testing.T) {
		// Test with invalid flate data
		invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		_, err := decompress(invalidData)
		assert.Error(t, err)
	})

	t.Run("encrypt/decrypt with exact boundary sizes", func(t *testing.T) {
		// Test exactly at the boundary sizes
		exactKey := make([]byte, chacha20poly1305.KeySize)
		exactNonce := make([]byte, chacha20poly1305.NonceSize)
		_, err := rand.Read(exactKey)
		require.NoError(t, err)
		_, err = rand.Read(exactNonce)
		require.NoError(t, err)

		testData := []byte("boundary test data")

		encrypted, err := encryptData(testData, exactKey, exactNonce)
		require.NoError(t, err)

		decrypted, err := decryptData(encrypted, exactKey, exactNonce)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("encrypt/decrypt with oversized key and nonce", func(t *testing.T) {
		// Test with key and nonce larger than required
		oversizedKey := make([]byte, chacha20poly1305.KeySize+10)
		oversizedNonce := make([]byte, chacha20poly1305.NonceSize+10)
		_, err := rand.Read(oversizedKey)
		require.NoError(t, err)
		_, err = rand.Read(oversizedNonce)
		require.NoError(t, err)

		testData := []byte("oversized test data")

		encrypted, err := encryptData(testData, oversizedKey, oversizedNonce)
		require.NoError(t, err)

		decrypted, err := decryptData(encrypted, oversizedKey, oversizedNonce)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("encrypt/decrypt with empty data", func(t *testing.T) {
		key := make([]byte, chacha20poly1305.KeySize)
		nonce := make([]byte, chacha20poly1305.NonceSize)
		_, err := rand.Read(key)
		require.NoError(t, err)
		_, err = rand.Read(nonce)
		require.NoError(t, err)

		testData := []byte{}

		encrypted, err := encryptData(testData, key, nonce)
		require.NoError(t, err)

		decrypted, err := decryptData(encrypted, key, nonce)
		require.NoError(t, err)

		// Both should be empty byte slices
		assert.Empty(t, decrypted)
	})
}
