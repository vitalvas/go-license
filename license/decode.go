package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
)

// DecodeFile decodes the PEM encoded license file and verifies the content signature using the ed25519 public key.
func DecodeFile(path string, publicKeys ...ed25519.PublicKey) (*License, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return Decode(data, publicKeys...)
}

// Decode decodes the PEM encoded license key and verifies the content signature using the ed25519 public key.
func Decode(data []byte, publicKeys ...ed25519.PublicKey) (*License, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "LICENSE KEY" {
		return nil, ErrMalformedLicense
	}

	decompressed, err := decompress(block.Bytes)
	if err != nil {
		return nil, err
	}

	var content licenseContent
	if err := json.Unmarshal(decompressed, &content); err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(content.Sign)
	if err != nil {
		return nil, err
	}

	msgHashSum, err := base64.RawURLEncoding.DecodeString(content.DataHash)
	if err != nil {
		return nil, err
	}

	encryptedData, err := base64.RawURLEncoding.DecodeString(content.Data)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptData(encryptedData, signature, msgHashSum)
	if err != nil {
		return nil, err
	}

	msgHash := sha256.New()
	if _, err = msgHash.Write(decryptedData); err != nil {
		return nil, err
	}
	msgHashCheckSum := msgHash.Sum(nil)

	if !bytes.Equal(msgHashCheckSum, msgHashSum) {
		return nil, ErrWrongVerifyChecksum
	}

	if publicKeys != nil {
		if verified := verifySignature(decryptedData, signature, publicKeys); !verified {
			return nil, ErrVerifySignature
		}
	}

	var license License

	if err := json.Unmarshal(decryptedData, &license); err != nil {
		return nil, err
	}

	if license.ID != block.Headers["id"] {
		return nil, ErrWrongVerifyID
	}

	return &license, nil
}

func verifySignature(message, sig []byte, publicKeys []ed25519.PublicKey) bool {
	for _, key := range publicKeys {
		if verified := ed25519.Verify(key, message, sig); verified {
			return true
		}
	}

	return false
}
