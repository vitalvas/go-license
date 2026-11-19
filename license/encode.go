package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
)

// validLicenseID reports whether id survives a PEM header round-trip. PEM
// decoding trims surrounding whitespace from header values, and a newline
// terminates the header line, so either would corrupt the stored id.
func validLicenseID(id string) bool {
	if id != strings.TrimSpace(id) {
		return false
	}

	return !strings.Contains(id, "\n")
}

func (lic *License) Encode(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(lic.ID) == 0 {
		return nil, ErrLicenseIDNotDefined
	}

	// The ID is stored in a PEM header and verified on decode. PEM header
	// values are trimmed and a newline ends the header line, so an ID that is
	// not round-trip safe would fail its own verification.
	if !validLicenseID(lic.ID) {
		return nil, ErrInvalidLicenseID
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
