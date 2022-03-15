package license

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
)

type Loader struct {
	licKey []byte
	rsaKey rsa.PublicKey
}

func Load(key []byte) *Loader {
	return &Loader{
		licKey: key,
	}
}

func (l *Loader) LoadPublicKey(key rsa.PublicKey) {
	l.rsaKey = key
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

	var content LicenseContent
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

	if bytes.Compare(msgHashCheckSum, msgHashSum) != 0 {
		return nil, errors.New("wrong verify checksum")
	}

	if err := rsa.VerifyPSS(&l.rsaKey, crypto.SHA256, msgHashSum, signature, nil); err != nil {
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
