////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package api

import (
	"gitlab.com/privategrity/client/crypto"
	"gitlab.com/privategrity/client/globals"
	"gitlab.com/privategrity/client/io"
)

func Login(userId int, serverAddress string) bool {
	isValidUser := globals.Session.Login(uint64(userId), serverAddress)
	if isValidUser {
		pollWaitTimeMillis := uint64(1000)
		io.InitReceptionRunner(pollWaitTimeMillis, globals.Session.GetNodeAddress())
	}
	return isValidUser
}

func Send(recipientID int, message string) {
	// NewMessage takes the ID of the sender, not the recipient
	sender := globals.Session.GetCurrentUser()
	newMessage := globals.NewMessage(sender.Id, message)

	// Prepare the new message to be sent
	payload, rid := crypto.Encrypt(newMessage, uint64(recipientID))
	// Send the message
	io.TransmitMessage(globals.Session.GetNodeAddress(), payload, rid)
}

func TryReceive() string {
	message := globals.Session.PopFifo()
	if message != nil {
		return message.GetStringPayload()
	} else {
		return ""
	}
}

func GetNick(userId int) string {
	user, ok := globals.Users.GetUser(uint64(userId))
	if ok && user != nil {
		return user.Nick
	} else {
		return ""
	}
}

// Logout closes the connection to the server at this time and does
// nothing with the user id. In the future this will release resources
// and safely release any sensitive memory.
func Logout(userId int, serverAddress string) bool {
	io.Disconnect(serverAddress)
	return true
}
