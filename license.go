package license

import "time"

type License struct {
	ID           string            `json:"id,omitempty"`
	Licensed     map[string]string `json:"licensed,omitempty"`
	IssuedAt     int64             `json:"issued_at,omitempty"`
	ExpiredAt    int64             `json:"expired_at,omitempty"`
	Features     []string          `json:"features,omitempty"`
	Restrictions map[string]int64  `json:"restrictions,omitempty"`
}

func (lic *License) HasExpired() bool {
	if lic.ExpiredAt > 0 && time.Now().UTC().Unix() >= int64(lic.ExpiredAt) {
		return true
	}

	return false
}
