package context

import (
	"gitlab.com/elixxir/client/context/message"
	"gitlab.com/elixxir/client/context/params"
	"gitlab.com/elixxir/client/context/stoppable"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
)

type NetworkManager interface {
	SendE2E(m message.Message, e2eP params.E2E, cmixP params.CMIX) ([]id.Round, error)
	SendUnsafe(m message.Message) ([]id.Round, error)
	SendCMIX(message format.Message) (id.Round, error)
	GetInstance() *network.Instance
	Stoppable() stoppable.Stoppable
}
