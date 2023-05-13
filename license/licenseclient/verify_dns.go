package licenseclient

import (
	"fmt"
	"net"
	"strings"

	"github.com/vitalvas/go-license/license"
)

func (c *Client) DNSVerify(lic *license.License) bool {
	if lic.Expired() {
		return false
	}

	fingerprint, err := lic.GetFingerprint()
	if err != nil {
		return false
	}

	var verified bool
	for _, host := range c.DNSHosts {
		if verified {
			break
		}

		records, err := net.LookupTXT(fmt.Sprintf("%s.%s", lic.ID, host))
		if err != nil {
			continue
		}

		for _, row := range records {
			if !verified && strings.TrimSpace(row) == fingerprint {
				verified = true
				break
			}
		}
	}

	return verified
}
