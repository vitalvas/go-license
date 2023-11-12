package license

import (
	"encoding/base64"
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

func TestGetFingerprint(t *testing.T) {
	license := &License{}

	hash, err := license.GetFingerprint()
	if err != nil {
		t.Error(err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(hash)
	if err != nil {
		t.Error(err)
	}

	if len(decoded) != 32 {
		t.Errorf("Expect fingerprint to be 32 bytes")
	}

	if hash != "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o" {
		t.Errorf("Expect fingerprint to match")
	}
}
