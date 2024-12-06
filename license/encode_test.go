package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestEncodeError(t *testing.T) {
	license := &License{}

	_, err := license.Encode(nil)
	if err == nil {
		t.Error("Expect error when encoding with nil key")
	}
}

func TestEncodeErrorID(t *testing.T) {
	license := &License{}

	_, err := license.Encode(nil)
	if err != ErrLicenseIDNotDefined {
		t.Errorf("Expect error %v, got %v", ErrLicenseIDNotDefined, err)
	}
}

func TestEncodeErrorExpired(t *testing.T) {
	license := &License{
		ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
		IssuedAt:  time.Now().Unix(),
		ExpiredAt: time.Now().Add(time.Hour * -1).Unix(),
	}

	if _, err := license.Encode(nil); err != ErrTime {
		t.Errorf("Expect error %v, got %v", ErrTime, err)
	}
}

func TestEncodeErrorPrivateKey(t *testing.T) {
	license := &License{
		ID:        "f3a2b3e9-107a-498a-9b5d-24812371ee87",
		IssuedAt:  time.Now().Unix(),
		ExpiredAt: time.Now().Add(time.Hour).Unix(),
	}

	if _, err := license.Encode(nil); err != ErrPrivateKeyNotDefined {
		t.Errorf("Expect error %v, got %v", ErrPrivateKeyNotDefined, err)
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

	//nolint:staticcheck
	if decoded == nil {
		t.Error("decoded data is empty")
	}

	//nolint:staticcheck
	if got, want := decoded.ID, license.ID; got != want {
		t.Errorf("Want license ID %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.Customer, license.Customer; got != want {
		t.Errorf("Want license Customer %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.Subscription, license.Subscription; got != want {
		t.Errorf("Want license Subscription %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.Type, license.Type; got != want {
		t.Errorf("Want license Type %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.IssuedAt, license.IssuedAt; got != want {
		t.Errorf("Want license IssuedAt %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.ExpiredAt, license.ExpiredAt; got != want {
		t.Errorf("Want license ExpiredAt %v, got %v", want, got)
	}

	//nolint:staticcheck
	if got, want := decoded.Data, license.Data; !bytes.Equal(got, want) {
		t.Errorf("Want license Data %v, got %v", want, got)
	}
}
