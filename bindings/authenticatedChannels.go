package bindings

// Create an insecure e2e relationship with a precanned user
func (c *Client) MakePrecannedAuthenticatedChannel(precannedID int) Contact {
	return c.api.MakePrecannedContact(uint(precannedID))
}
