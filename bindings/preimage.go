package bindings

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
)

type PreimageNotification interface {
	Notify(identity []byte, deleted bool)
}

func (c *Client) RegisterPreimageCallback(identity []byte, pin PreimageNotification) {

	iid := &id.ID{}
	copy(iid[:], identity)

	cb := func(localIdentity *id.ID, deleted bool) {
		pin.Notify(localIdentity[:], deleted)
	}

	c.api.GetStorage().GetEdge().AddUpdateCallback(iid, cb)
}

func (c *Client) GetPreimages(identity []byte) (string, error) {

	iid := &id.ID{}
	copy(iid[:], identity)

	list, exist := c.api.GetStorage().GetEdge().Get(iid)
	if !exist {
		return "", errors.Errorf("Could not find a preimage list for %s", iid)
	}

	marshaled, err := json.Marshal(&list)

	return string(marshaled), err
}

func (c *Client) GetPreimagesB64(identity string) (string, error) {
	iid := &id.ID{}
	decoded, err := base64.StdEncoding.DecodeString(identity)
	if err != nil {
		return "", err
	}
	copy(iid[:], decoded)

	list, exist := c.api.GetStorage().GetEdge().Get(iid)
	if !exist {
		return "", errors.Errorf("Could not find a preimage list for %s", iid)
	}

	marshaled, err := json.Marshal(&list)

	return string(marshaled), err
}

// hack on getPreimages so it works on iOS per https://github.com/golang/go/issues/46893
func (c *Client) GetPreimagesHack(dummy string, identity []byte) (string, error) {

	iid := &id.ID{}
	copy(iid[:], identity)

	list, exist := c.api.GetStorage().GetEdge().Get(iid)
	if !exist {
		return "", errors.Errorf("Could not find a preimage list for %s", iid)
	}

	marshaled, err := json.Marshal(&list)

	return string(marshaled), err
}
