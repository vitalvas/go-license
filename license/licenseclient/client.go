package licenseclient

type Client struct {
	DNSHosts     []string
	APIEndpoints []string
}

func New() *Client {
	return &Client{}
}

func (c *Client) SetDNSHosts(hosts []string) *Client {
	c.DNSHosts = hosts
	return c
}

func (c *Client) SetAPIEndpoints(endpoints []string) *Client {
	c.APIEndpoints = endpoints
	return c
}
