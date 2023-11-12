package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

func (lic *License) Encode(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(lic.ID) == 0 {
		return nil, ErrLicenseIDNotDefined
	}

	if lic.ExpiredAt > 0 && lic.ExpiredAt <= lic.IssuedAt {
		return nil, ErrTime
	}

	if privateKey == nil {
		return nil, ErrPrivateKeyNotDefined
	}

	data, err := json.Marshal(lic)
	if err != nil {
		return nil, err
	}

	msgHashSum := sha256.Sum256(data)

	signature := ed25519.Sign(privateKey, data)

	encryptedData, err := encryptData(data, signature, msgHashSum[:])
	if err != nil {
		return nil, err
	}

	content := licenseContent{
		Data:     base64.RawURLEncoding.EncodeToString(encryptedData),
		Sign:     base64.RawURLEncoding.EncodeToString(signature),
		DataHash: base64.RawURLEncoding.EncodeToString(msgHashSum[:]),
	}

	dataContent, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}

	compressed, err := compress(dataContent)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "LICENSE KEY",
		Bytes: compressed,
		Headers: map[string]string{
			"id": lic.ID,
		},
	}), nil

}
