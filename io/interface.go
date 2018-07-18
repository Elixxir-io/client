////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// io sends and receives messages using gRPC
package io

import (
	"gitlab.com/privategrity/client/user"
	"time"
)

// Communication interface implements send/receive functionality with the server
type Communications interface {
	// SendMessage to the server
	SendMessage(recipientID user.ID, message string) error
	// MessageReceiver thread to get new messages
	MessageReceiver(delay time.Duration)
}
