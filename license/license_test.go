package license

import (
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
