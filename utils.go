package license

import (
	"bytes"
	"compress/flate"
	"io/ioutil"

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

func decompress(data []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(data))

	defer zr.Close()

	decompressed, err := ioutil.ReadAll(zr)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
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

func decryptData(data, key, nonce []byte) ([]byte, error) {
	encKey := key[:chacha20poly1305.KeySize]
	nonceKey := nonce[:chacha20poly1305.NonceSizeX]

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonceKey, data, nil)
}
