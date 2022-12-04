package license

import (
	"encoding/json"
	"time"
)

type License struct {
	ID        string          `json:"id,omitempty"`
	IssuedAt  int64           `json:"issued_at,omitempty"`
	ExpiredAt int64           `json:"expired_at,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

func (lic *License) HasExpired() bool {
	if lic.ExpiredAt > 0 && time.Now().UTC().Unix() >= lic.ExpiredAt {
		return true
	}

	return false
}

func (lic *License) Marshal() ([]byte, error) {
	return json.Marshal(lic)
}
