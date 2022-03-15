package license

import (
	"bytes"
	"compress/flate"

	"golang.org/x/crypto/chacha20poly1305"
)

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}

	if _, err := zw.Write(data); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func encryptData(data, key, nonce []byte) ([]byte, error) {
	encKey := key[:chacha20poly1305.KeySize]
	nonceKey := nonce[:chacha20poly1305.NonceSizeX]

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonceKey, data, nil), nil
}
