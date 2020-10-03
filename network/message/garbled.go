package message

import (
	"gitlab.com/elixxir/client/interfaces/message"
	"time"
)

// Messages can arrive in the network out of order. When message handling fails
// to decrypt a message, it is added to the garbled message buffer (which is
// stored on disk) and the message decryption is retried here whenever triggered.

// This can be triggered through the CheckGarbledMessages on the network manager
// and is used in the /keyExchange package on successful rekey triggering

// Triggers Garbled message checking if the queue is not full
// Exposed on the network manager
func (m *Manager) CheckGarbledMessages() {
	select {
	case m.triggerGarbled <- struct{}{}:
	default:
	}
}

//long running thread which processes garbled messages
func (m *Manager) processGarbledMessages(quitCh <-chan struct{}) {
	done := false
	for !done {
		select {
		case <-quitCh:
			done = true
		case <-m.triggerGarbled:
			m.handleGarbledMessages()
		}
	}
}

//handler for a single run of garbled messages
func (m *Manager) handleGarbledMessages() {
	garbledMsgs := m.Session.GetGarbledMessages()
	e2eKv := m.Session.E2e()
	//try to decrypt every garbled message, excising those who's counts are too high
	for grbldMsg, count, timestamp, has := garbledMsgs.Next(); has; grbldMsg, count, timestamp, has = garbledMsgs.Next() {
		fingerprint := grbldMsg.GetKeyFP()
		// Check if the key is there, process it if it is
		if key, isE2E := e2eKv.PopKey(fingerprint); isE2E {
			// Decrypt encrypted message
			msg, err := key.Decrypt(grbldMsg)
			// get the sender
			sender := key.GetSession().GetPartner()
			if err == nil {
				//remove from the buffer if decryption is successful
				garbledMsgs.Remove(grbldMsg)
				//handle the successfully decrypted message
				xxMsg, ok := m.partitioner.HandlePartition(sender, message.E2E,
					msg.GetContents(),
					key.GetSession().GetRelationshipFingerprint())
				if ok {
					m.Switchboard.Speak(xxMsg)
					continue
				}
			}
		}
		// fail the message if any part of the decryption fails,
		// unless it is the last attempts and has been in the buffer long
		// enough, in which case remove it
		if count == m.param.MaxChecksGarbledMessage &&
			time.Since(timestamp) > m.param.GarbledMessageWait {
			garbledMsgs.Remove(grbldMsg)
		} else {
			garbledMsgs.Failed(grbldMsg)
		}
	}
}
