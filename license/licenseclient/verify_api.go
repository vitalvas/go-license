package licenseclient

import "github.com/vitalvas/go-license/license"

func (c *Client) APIVerify(_ *license.License) bool {

	return false
}
