package license

import (
	"bytes"
	"compress/flate"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type licenseContent struct {
	Data     string `json:"d"`
	Sign     string `json:"s"`
	DataHash string `json:"h"`
}

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

func decompress(data []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(data))

	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}

func encryptData(data, key, nonce []byte) ([]byte, error) {
	encKey := key[:chacha20poly1305.KeySize]
	nonceKey := nonce[:chacha20poly1305.NonceSize]

	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonceKey, data, nil), nil
}

func decryptData(data, key, nonce []byte) ([]byte, error) {
	encKey := key[:chacha20poly1305.KeySize]
	nonceKey := nonce[:chacha20poly1305.NonceSize]

	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonceKey, data, nil)
}
