package licenseutil

import (
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/vitalvas/go-license/license"
)

type Generate struct {
	lic license.License
	key ed25519.PrivateKey
}

func NewGenerate() *Generate {
	return &Generate{
		lic: license.License{
			IssuedAt: time.Now().Truncate(time.Hour * 24).UTC().Unix(),
		},
	}
}

func (g *Generate) LoadPrivateKey(key ed25519.PrivateKey) {
	g.key = key
}

func (g *Generate) SetID(id string) {
	g.lic.ID = id
}

func (g *Generate) SetData(data interface{}) error {
	var err error

	g.lic.Data, err = json.Marshal(data)
	if err != nil {
		return err
	}

	return nil
}

func (g *Generate) SetIssued(ts time.Time) {
	g.lic.IssuedAt = ts.UTC().Unix()
}

func (g *Generate) SetExpired(ts time.Time) {
	g.lic.ExpiredAt = ts.UTC().Unix()
}

func (g *Generate) GetLicenseKey() ([]byte, error) {
	return g.lic.Encode(g.key)
}
