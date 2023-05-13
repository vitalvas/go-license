package licenseutil

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/vitalvas/go-license/license"
)

type Generate struct {
	lic license.License
	key ed25519.PrivateKey
}

type licenseContent struct {
	Data     string `json:"d"`
	Sign     string `json:"s"`
	DataHash string `json:"h"`
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
	if len(g.lic.ID) == 0 {
		return nil, errors.New("license id not defined")
	}

	if g.lic.ExpiredAt > 0 && g.lic.ExpiredAt <= g.lic.IssuedAt {
		return nil, errors.New("the expire time must be greater than the issue time")
	}

	data, err := g.lic.Marshal()
	if err != nil {
		return nil, err
	}

	msgHash := sha256.New()
	if _, err = msgHash.Write(data); err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	signature := ed25519.Sign(g.key, data)

	encryptedData, err := encryptData(data, signature, msgHashSum)
	if err != nil {
		return nil, err
	}

	content := licenseContent{
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
