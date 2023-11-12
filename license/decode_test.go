package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"time"
)

func TestDecodeWrongKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	license := &License{
		ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
		IssuedAt:  time.Now().Unix(),
		ExpiredAt: time.Now().Add(time.Hour).Unix(),
		Data:      []byte(`{"test":1}`),
	}

	encoded, err := license.Encode(privateKey)
	if err != nil {
		t.Error(err)
	}

	publicKeyWrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decode(encoded, publicKeyWrong)
	if err != ErrVerifySignature {
		t.Error(err)
	}
}

func TestDecodeEmpty(t *testing.T) {
	_, err := Decode(nil, nil)
	if err != ErrMalformedLicense {
		t.Error(ErrMalformedLicense)
	}
}

func TestDecodeNonKey(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{
		Type: "SOME ELSE",
	})

	_, err := Decode(data, nil)
	if err != ErrMalformedLicense {
		t.Error(ErrMalformedLicense)
	}
}
