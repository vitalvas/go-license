package licenseclient

import (
	"github.com/vitalvas/go-license/license"
)

func (c *Client) Verify(lic *license.License) bool {
	if c.DNSHosts != nil {
		if verified := c.DNSVerify(lic); verified {
			return true
		}
	}

	if c.APIEndpoints != nil {
		if verified := c.APIVerify(lic); verified {
			return true
		}
	}

	return false
}
