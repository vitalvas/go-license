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
