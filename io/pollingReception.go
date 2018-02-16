package io

import (
	"gitlab.com/privategrity/client/crypto"
	"gitlab.com/privategrity/client/globals"
	pb "gitlab.com/privategrity/comms/mixmessages"
	"gitlab.com/privategrity/comms/mixserver/message"
	"time"
)

func runfunc(wait uint64, addr string) {

	usr := globals.Session.GetCurrentUser()

	rqMsg := &pb.ClientPollMessage{UserID: usr.Id}

	for true {
		time.Sleep(time.Duration(wait) * time.Millisecond)

		cmixMsg, _ := message.SendClientPoll(addr, rqMsg)

		if len(cmixMsg.MessagePayload) != 0 {
			cmixmsgbuf := cmixMsg.MessagePayload[:]
			msg := crypto.Decrypt(&cmixmsgbuf)

			globals.Session.PushFifo(msg)
		}

	}
}

func InitReceptionRunner(wait uint64, addr string) {
	go runfunc(wait, addr)
}
