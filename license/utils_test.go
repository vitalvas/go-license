package license

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompress(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		output  []byte
		wantErr bool
	}{
		{
			name:    "Empty input",
			input:   []byte{},
			output:  []byte{0x1, 0x0, 0x0, 0xff, 0xff},
			wantErr: false,
		},
		{
			name:  "Valid input",
			input: []byte("This is a test string"),
			output: []byte{
				0xa, 0xc9, 0xc8, 0x2c, 0x56, 0xc8, 0x2c, 0x56, 0x48, 0x54, 0x28, 0x49, 0x2d, 0x2e, 0x51, 0x28,
				0x2e, 0x29, 0xca, 0xcc, 0x4b, 0x7, 0x4, 0x0, 0x0, 0xff, 0xff,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("compress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.output, got)

			if !tt.wantErr {
				// Decompress to verify the result
				zr := flate.NewReader(bytes.NewReader(got))
				defer zr.Close()

				decompressed, err := io.ReadAll(zr)
				assert.Nil(t, err)

				assert.Equal(t, tt.input, decompressed)
			}
		})
	}
}
func TestDecompress(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		output  []byte
		wantErr bool
	}{
		{
			name:    "Empty input",
			input:   []byte{0x1, 0x0, 0x0, 0xff, 0xff},
			output:  []byte{},
			wantErr: false,
		},
		{
			name: "Valid input",
			input: []byte{
				0xa, 0xc9, 0xc8, 0x2c, 0x56, 0xc8, 0x2c, 0x56, 0x48, 0x54, 0x28, 0x49, 0x2d, 0x2e, 0x51, 0x28,
				0x2e, 0x29, 0xca, 0xcc, 0x4b, 0x7, 0x4, 0x0, 0x0, 0xff, 0xff,
			},
			output:  []byte("This is a test string"),
			wantErr: false,
		},
		{
			name:    "Invalid input",
			input:   []byte{0x0, 0x1, 0x2, 0x3},
			output:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decompress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decompress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.output, got)
		})
	}
}
func TestEncryptData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		key     []byte
		nonce   []byte
		wantErr bool
	}{
		{
			name:    "Valid input",
			data:    []byte("This is a test string"),
			key:     []byte("12345678901234567890123456789012"), // 32 bytes key
			nonce:   []byte("123456789012"),                     // 12 bytes nonce
			wantErr: false,
		},
		{
			name:    "Invalid key length",
			data:    []byte("This is a test string"),
			key:     []byte("shortkey"), // Invalid key length
			nonce:   []byte("123456789012"),
			wantErr: true,
		},
		{
			name:    "Invalid nonce length",
			data:    []byte("This is a test string"),
			key:     []byte("12345678901234567890123456789012"),
			nonce:   []byte("shortnonce"), // Invalid nonce length
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptData(tt.data, tt.key, tt.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assert.NotNil(t, got)
				assert.NotEqual(t, tt.data, got)
			}
		})
	}
}
func TestDecryptData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		key     []byte
		nonce   []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "Valid input",
			data: func() []byte {
				encrypted, _ := encryptData(
					[]byte("This is a test string"),
					[]byte("12345678901234567890123456789012"),
					[]byte("123456789012"),
				)
				return encrypted
			}(),
			key:     []byte("12345678901234567890123456789012"), // 32 bytes key
			nonce:   []byte("123456789012"),                     // 12 bytes nonce
			want:    []byte("This is a test string"),
			wantErr: false,
		},
		{
			name:    "Invalid key length",
			data:    []byte("This is a test string"),
			key:     []byte("shortkey"), // Invalid key length
			nonce:   []byte("123456789012"),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid nonce length",
			data:    []byte("This is a test string"),
			key:     []byte("12345678901234567890123456789012"),
			nonce:   []byte("shortnonce"), // Invalid nonce length
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid encrypted data",
			data:    []byte("invalid encrypted data"),
			key:     []byte("12345678901234567890123456789012"),
			nonce:   []byte("123456789012"),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decryptData(tt.data, tt.key, tt.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("decryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
