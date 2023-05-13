package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	license := &License{}

	if license.Expired() {
		t.Errorf("Expect zero value expiration to never expire")
	}

	license.ExpiredAt = time.Now().Add(time.Hour).Unix()
	if license.Expired() == true {
		t.Errorf("Expect license is not expired")
	}

	license.ExpiredAt = time.Now().Add(time.Hour * -1).Unix()
	if license.Expired() == false {
		t.Errorf("Expect license is expired")
	}
}

func TestEncodeDecode(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	license := &License{
		ID:           "f3a2b3e9-107a-498a-9b5d-24812371ee87",
		Customer:     "fa4dfb36-b26c-4921-95f5-ffa494e688c1",
		Subscription: "31d853e6-d253-4782-adb6-35b85b482c93",
		Type:         "online",
		IssuedAt:     time.Now().Unix(),
		ExpiredAt:    time.Now().Add(time.Hour).Unix(),
		Data:         []byte(`{"test":1}`),
	}

	encoded, err := license.Encode(privateKey)
	if err != nil {
		t.Error(err)
	}

	if encoded == nil {
		t.Error("encoded data is empty")
	}

	decoded, err := Decode(encoded, publicKey)
	if err != nil {
		t.Error(err)
	}

	if decoded == nil {
		t.Error("decoded data is empty")
	}

	if got, want := decoded.ID, license.ID; got != want {
		t.Errorf("Want license ID %v, got %v", want, got)
	}

	if got, want := decoded.Customer, license.Customer; got != want {
		t.Errorf("Want license Customer %v, got %v", want, got)
	}

	if got, want := decoded.Subscription, license.Subscription; got != want {
		t.Errorf("Want license Subscription %v, got %v", want, got)
	}

	if got, want := decoded.Type, license.Type; got != want {
		t.Errorf("Want license Type %v, got %v", want, got)
	}

	if got, want := decoded.IssuedAt, license.IssuedAt; got != want {
		t.Errorf("Want license IssuedAt %v, got %v", want, got)
	}

	if got, want := decoded.ExpiredAt, license.ExpiredAt; got != want {
		t.Errorf("Want license IssuedAt %v, got %v", want, got)
	}

	if got, want := decoded.Data, license.Data; !bytes.Equal(got, want) {
		t.Errorf("Want license IssuedAt %v, got %v", want, got)
	}
}

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
