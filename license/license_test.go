package license

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func TestGetFingerprint(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		license := &License{
			ID: "123",
		}

		hash, err := license.GetFingerprint()
		if err != nil {
			t.Error(err)
		}

		decoded, err := base64.RawURLEncoding.DecodeString(hash)
		if err != nil {
			t.Error(err)
		}

		assert.Len(t, decoded, 32)

		assert.Equal(t, "ECcsha9GmtgfZtn17D76cO4Kx7kfqeBd2prdVKYGID4", hash)
	})

	t.Run("Empty", func(t *testing.T) {
		license := &License{}

		hash, err := license.GetFingerprint()
		assert.Nil(t, err)

		assert.Equal(t, "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o", hash)
	})
}
