package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	_ "crypto/sha256"
)

type Generate struct {
	lic License
	key *rsa.PrivateKey
}

type LicenseContent struct {
	Data     string `json:"data"`
	Sign     string `json:"sign"`
	DataHash string `json:"dh"`
}

func NewGenerate() *Generate {
	return &Generate{
		lic: License{
			IssuedAt: time.Now().Truncate(time.Hour * 24).UTC().Unix(),
		},
	}
}

func (g *Generate) LoadPrivateKey(key *rsa.PrivateKey) {
	g.key = key
}

func (g *Generate) Set(key, value string) {
	if g.lic.Licensed == nil {
		g.lic.Licensed = make(map[string]string)
	}

	g.lic.Licensed[key] = value
}

func (g *Generate) SetID(id string) {
	g.lic.ID = id
}

func (g *Generate) SetIssued(ts time.Time) {
	g.lic.IssuedAt = ts.UTC().Unix()
}

func (g *Generate) SetExpired(ts time.Time) {
	g.lic.ExpiredAt = ts.UTC().Unix()
}

func (g *Generate) SetFeature(key string) {
	for _, row := range g.lic.Features {
		if row == key {
			return
		}
	}

	g.lic.Features = append(g.lic.Features, key)
}

func (g *Generate) SetRestriction(key string, value int64) {
	if g.lic.Restrictions == nil {
		g.lic.Restrictions = make(map[string]int64)
	}

	g.lic.Restrictions[key] = value
}

func (g *Generate) GetLicenseKey() ([]byte, error) {
	if len(g.lic.ID) == 0 {
		return nil, errors.New("license id not defined")
	}

	if g.lic.ExpiredAt > 0 && g.lic.ExpiredAt <= g.lic.IssuedAt {
		return nil, errors.New("the expire time must be greater than the issue time")
	}

	data, err := json.Marshal(g.lic)
	if err != nil {
		return nil, err
	}

	msgHash := sha256.New()
	if _, err = msgHash.Write(data); err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, g.key, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encryptData(data, signature, msgHashSum)
	if err != nil {
		return nil, err
	}

	content := LicenseContent{
		Data:     base64.RawURLEncoding.EncodeToString(encryptedData),
		Sign:     base64.RawURLEncoding.EncodeToString(signature),
		DataHash: base64.RawURLEncoding.EncodeToString(msgHashSum),
	}

	dataContent, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}

	compressed, err := compress(dataContent)
	if err != nil {
		return nil, err
	}

	keyHeaders := map[string]string{
		"id": g.lic.ID,
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    "LICENSE KEY",
		Headers: keyHeaders,
		Bytes:   compressed,
	}), nil
}
