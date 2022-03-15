package license

import "time"

type License struct {
	ID           string            `json:"id"`
	Licensed     map[string]string `json:"licensed"`
	IssuedAt     uint32            `json:"issued_at"`
	ExpiredAt    uint32            `json:"expired_at"`
	Features     []string          `json:"features"`
	Restrictions map[string]uint64 `json:"restrictions"`
}

func (lic *License) HasExpired() bool {
	if lic.ExpiredAt > 0 && time.Now().UTC().Unix() >= int64(lic.ExpiredAt) {
		return true
	}

	return false
}
