package context

import (
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/client/switchboard"
	"gitlab.com/elixxir/crypto/fastRNG"
)

type Context struct {
	Session     *storage.Session
	Switchboard *switchboard.Switchboard
	// note that the manager has a pointer to the context in many cases, but
	// this interface allows it to be mocked for easy testing without the
	// loop
	Manager NetworkManager
	//generic RNG for client
	Rng *fastRNG.StreamGenerator
}
