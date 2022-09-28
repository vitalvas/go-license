package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
)

type Loader struct {
	licKey []byte
	pubKey []ed25519.PublicKey
}

func Load(key []byte) *Loader {
	return &Loader{
		licKey: key,
	}
}

func (l *Loader) LoadPublicKey(keys []ed25519.PublicKey) {
	l.pubKey = keys
}

func (l *Loader) GetLicense() (*License, error) {
	block, _ := pem.Decode(l.licKey)
	if block == nil || block.Type != "LICENSE KEY" {
		return nil, errors.New("can not decode block key")
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
		return nil, errors.New("wrong verify checksum")
	}

	if err := l.verify(decryptedData, signature); err != nil {
		return nil, err
	}

	var license License

	if err := json.Unmarshal(decryptedData, &license); err != nil {
		return nil, err
	}

	if license.ID != block.Headers["id"] {
		return nil, errors.New("wrong verify id")
	}

	return &license, nil
}

func (l *Loader) verify(message, sig []byte) error {
	for _, key := range l.pubKey {
		if verified := ed25519.Verify(key, message, sig); verified {
			return nil
		}
	}

	return errors.New("error verify signature")
}
