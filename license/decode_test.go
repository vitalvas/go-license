package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	t.Run("WrongSignature", func(t *testing.T) {
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
	})

	t.Run("CorrectSignature", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
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

		_, err = Decode(encoded, publicKey)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("DecodeWithoutCheckSignature", func(t *testing.T) {
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

		_, err = Decode(encoded)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("DecodeEmpty", func(t *testing.T) {
		_, err := Decode(nil, nil)
		if err != ErrMalformedLicense {
			t.Error(err)
		}
	})

	t.Run("DecodeMalformed", func(t *testing.T) {
		_, err := Decode([]byte("MALFORMED"), nil)
		if err != ErrMalformedLicense {
			t.Error(err)
		}
	})
}
func TestVerifySignature(t *testing.T) {
	t.Run("ValidSignature", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		message := []byte("test message")
		signature := ed25519.Sign(privateKey, message)

		if !verifySignature(message, signature, []ed25519.PublicKey{publicKey}) {
			t.Error("expected signature to be valid")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		message := []byte("test message")
		invalidSignature := make([]byte, ed25519.SignatureSize)

		if verifySignature(message, invalidSignature, []ed25519.PublicKey{publicKey}) {
			t.Error("expected signature to be invalid")
		}
	})

	t.Run("NoPublicKeys", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, ed25519.SignatureSize)

		if verifySignature(message, signature, nil) {
			t.Error("expected signature to be invalid with no public keys")
		}
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		message := []byte("test message")
		signature := make([]byte, ed25519.SignatureSize)

		if verifySignature(message, signature, []ed25519.PublicKey{nil}) {
			t.Error("expected signature to be invalid with invalid public key")
		}
	})

	t.Run("MultiplePublicKeys", func(t *testing.T) {
		publicKey1, privateKey1, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		message := []byte("test message")
		signature := ed25519.Sign(privateKey1, message)

		if !verifySignature(message, signature, []ed25519.PublicKey{publicKey2, publicKey1}) {
			t.Error("expected signature to be valid with one correct public key")
		}
	})
}
