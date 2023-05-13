package license

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

type License struct {
	ID           string          `json:"id,omitempty"`  // License ID
	Customer     string          `json:"cus,omitempty"` // Customer ID
	Subscription string          `json:"sub,omitempty"` // Subscription ID
	Type         string          `json:"typ,omitempty"` // License Type
	IssuedAt     int64           `json:"iat,omitempty"` // Issued At
	ExpiredAt    int64           `json:"exp,omitempty"` // Expires At
	Data         json.RawMessage `json:"dat,omitempty"` // Metadata
}

// Expired returns true if the license is expired.
func (lic *License) Expired() bool {
	if lic.ExpiredAt > 0 && time.Now().UTC().Unix() >= lic.ExpiredAt {
		return true
	}

	return false
}

func (lic *License) GetFingerprint() (string, error) {
	licData, err := json.Marshal(lic)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(licData)

	hashBase64 := base64.RawURLEncoding.EncodeToString(hash[:])

	return hashBase64, nil
}
