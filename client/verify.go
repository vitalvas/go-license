package client

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/vitalvas/go-license"
	"golang.org/x/crypto/blake2b"
)

func (c *Client) Verify(lic *license.License) bool {
	if c.DNSHosts != nil {
		if verified := c.DNSVerify(lic); verified {
			return true
		}
	}

	return false
}

func (c *Client) DNSVerify(lic *license.License) bool {
	if lic.HasExpired() {
		return false
	}

	licData, err := lic.Marshal()
	if err != nil {
		return false
	}

	hash := blake2b.Sum256(licData)
	hashBase64 := base64.RawURLEncoding.EncodeToString(hash[:])

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
			if verified {
				break
			}

			if strings.TrimSpace(row) == hashBase64 {
				verified = true
			}
		}
	}

	return verified
}
