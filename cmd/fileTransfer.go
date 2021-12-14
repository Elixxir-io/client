////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/viper"
	"gitlab.com/elixxir/client/api"
	ft "gitlab.com/elixxir/client/fileTransfer"
	"gitlab.com/elixxir/client/interfaces"
	"gitlab.com/elixxir/crypto/contact"
	ftCrypto "gitlab.com/elixxir/crypto/fileTransfer"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"gitlab.com/xx_network/primitives/utils"
	"io/ioutil"
	"strconv"
	"time"
)

const callbackPeriod = 25 * time.Millisecond

// ftCmd starts the file transfer manager and allows the sending and receiving
// of files.
var ftCmd = &cobra.Command{
	Use:   "fileTransfer",
	Short: "Send and receive file for cMix client",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		// Initialise a new client
		client := initClient()

		// Print user's reception ID and save contact file
		user := client.GetUser()
		jww.INFO.Printf("User: %s", user.ReceptionID)
		writeContact(user.GetContact())

		// Start the network follower
		err := client.StartNetworkFollower(5 * time.Second)
		if err != nil {
			jww.FATAL.Panicf("Failed to start the network follower: %+v", err)
		}

		// Initialize the file transfer manager
		maxThroughput := viper.GetInt("maxThroughput")
		m, receiveChan := initFileTransferManager(client, maxThroughput)

		// Wait until connected or crash on timeout
		connected := make(chan bool, 10)
		client.GetHealth().AddChannel(connected)
		waitUntilConnected(connected)

		// After connection, wait until registered with at least 85% of nodes
		for numReg, total := 1, 100; numReg < (total*3)/4; {
			time.Sleep(1 * time.Second)

			numReg, total, err = client.GetNodeRegistrationStatus()
			if err != nil {
				jww.FATAL.Panicf("Failed to get node registration status: %+v",
					err)
			}

			jww.INFO.Printf("Registering with nodes (%d/%d)...", numReg, total)
		}

		// Start thread that receives new file transfers and prints them to log
		receiveQuit := make(chan struct{})
		receiveDone := make(chan struct{})
		go receiveNewFileTransfers(receiveChan, receiveDone, receiveQuit, m)

		// If set, send the file to the recipient
		sendDone := make(chan struct{})
		if viper.IsSet("sendFile") {
			recipientContactPath := viper.GetString("sendFile")
			filePath := viper.GetString("filePath")
			fileType := viper.GetString("fileType")
			filePreviewPath := viper.GetString("filePreviewPath")
			filePreviewString := viper.GetString("filePreviewString")
			retry := float32(viper.GetFloat64("retry"))

			sendFile(filePath, fileType, filePreviewPath, filePreviewString,
				recipientContactPath, retry, m, sendDone)
		}

		// Wait until either the file finishes sending or the file finishes
		// being received, stop the receiving thread, and exit
		for done := false; !done; {
			select {
			case <-sendDone:
				jww.DEBUG.Printf("Finished sending file. Stopping threads " +
					"and network follower.")
				done = true
			case <-receiveDone:
				jww.DEBUG.Printf("Finished receiving file. Stopping " +
					"threads and network follower.")
				done = true
			}
		}

		// Stop reception thread
		receiveQuit <- struct{}{}

		// Stop network follower
		err = client.StopNetworkFollower()
		if err != nil {
			jww.WARN.Printf("Failed to stop network follower: %+v", err)
		}

		jww.DEBUG.Print("File transfer finished stopping threads and network " +
			"follower.")
	},
}

// receivedFtResults is used to return received new file transfer results on a
// channel from a callback.
type receivedFtResults struct {
	tid      ftCrypto.TransferID
	fileName string
	fileType string
	sender   *id.ID
	size     uint32
	preview  []byte
}

// initFileTransferManager creates a new file transfer manager with a new
// reception callback. Returns the file transfer manager and the channel that
// will be triggered when the callback is called.
func initFileTransferManager(client *api.Client, maxThroughput int) (
	*ft.Manager, chan receivedFtResults) {

	// Create interfaces.ReceiveCallback that returns the results on a channel
	receiveChan := make(chan receivedFtResults, 100)
	receiveCB := func(tid ftCrypto.TransferID, fileName, fileType string,
		sender *id.ID, size uint32, preview []byte) {
		receiveChan <- receivedFtResults{
			tid, fileName, fileType, sender, size, preview}
	}

	// Create new parameters
	p := ft.DefaultParams()
	if maxThroughput != 0 {
		p = ft.NewParams(maxThroughput)
	}

	// Create new manager
	manager, err := ft.NewManager(client, receiveCB, p)
	if err != nil {
		jww.FATAL.Panicf("Failed to create new file transfer manager: %+v", err)
	}

	// Start the file transfer sending and receiving threads
	err = client.AddService(manager.StartProcesses)
	if err != nil {
		jww.FATAL.Panicf("Failed to start file transfer threads: %+v", err)
	}

	return manager, receiveChan
}

// sendFile sends the file to the recipient and prints the progress.
func sendFile(filePath, fileType, filePreviewPath, filePreviewString,
	recipientContactPath string, retry float32, m *ft.Manager,
	done chan struct{}) {

	// Get file from path
	fileData, err := utils.ReadFile(filePath)
	if err != nil {
		jww.FATAL.Panicf("Failed to read file %q: %+v", filePath, err)
	}

	// Get file preview from path
	filePreviewData := []byte(filePreviewString)
	if filePreviewPath != "" {
		filePreviewData, err = utils.ReadFile(filePreviewPath)
		if err != nil {
			jww.FATAL.Panicf("Failed to read file preview %q: %+v",
				filePreviewPath, err)
		}
	}

	// Get recipient contact from file
	recipient := getContactFromFile(recipientContactPath)

	jww.DEBUG.Printf("Sending file %q of size %d to recipient %s.",
		filePath, len(fileData), recipient.ID)

	// Create sent progress callback that prints the results
	progressCB := func(completed bool, sent, arrived, total uint16,
		t interfaces.FilePartTracker, err error) {
		jww.DEBUG.Printf("Sent progress callback for %q "+
			"{completed: %t, sent: %d, arrived: %d, total: %d, err: %v}\n",
			filePath, completed, sent, arrived, total, err)
		if (sent == 0 && arrived == 0) || (arrived == total) || completed ||
			err != nil {
			fmt.Printf("Sent progress callback for %q "+
				"{completed: %t, sent: %d, arrived: %d, total: %d, err: %v}\n",
				filePath, completed, sent, arrived, total, err)
		}

		if completed {
			fmt.Printf("Completed sending file.\n")
			done <- struct{}{}
		} else if err != nil {
			fmt.Printf("Failed sending file: %+v\n", err)
			done <- struct{}{}
		}
	}

	// Send the file
	_, err = m.Send(filePath, fileType, fileData, recipient.ID, retry,
		filePreviewData, progressCB, callbackPeriod)
	if err != nil {
		jww.FATAL.Panicf("Failed to send file %q to %s: %+v",
			filePath, recipient.ID, err)
	}
}

// receiveNewFileTransfers waits to receive new file transfers and prints its
// information to the log.
func receiveNewFileTransfers(receive chan receivedFtResults, done,
	quit chan struct{}, m *ft.Manager) {
	jww.DEBUG.Print("Starting thread waiting to receive NewFileTransfer " +
		"E2E message.")
	for {
		select {
		case <-quit:
			jww.DEBUG.Print("Quitting thread waiting for NewFileTransfer E2E " +
				"message.")
			return
		case r := <-receive:
			jww.DEBUG.Printf("Received new file %q transfer %s from %s of size %d "+
				"bytes with preview: %q",
				r.fileName, r.tid, r.sender, r.size, r.preview)
			fmt.Printf("Received new file transfer %q of size %d "+
				"bytes with preview: %q\n", r.fileName, r.size, r.preview)

			cb := newReceiveProgressCB(r.tid, done, m)
			err := m.RegisterReceiveProgressCallback(r.tid, cb, callbackPeriod)
			if err != nil {
				jww.FATAL.Panicf("Failed to register new receive progress "+
					"callback for transfer %s: %+v", r.tid, err)
			}
		}
	}
}

// newReceiveProgressCB creates a new reception progress callback that prints
// the results to the log.
func newReceiveProgressCB(tid ftCrypto.TransferID, done chan struct{},
	m *ft.Manager) interfaces.ReceivedProgressCallback {
	return func(completed bool, received, total uint16,
		t interfaces.FilePartTracker, err error) {
		jww.DEBUG.Printf("Receive progress callback for transfer %s "+
			"{completed: %t, received: %d, total: %d, err: %v}",
			tid, completed, received, total, err)

		if received == total || completed || err != nil {
			fmt.Printf("Received progress callback "+
				"{completed: %t, received: %d, total: %d, err: %v}\n",
				completed, received, total, err)
		}

		if completed {
			receivedFile, err2 := m.Receive(tid)
			if err2 != nil {
				jww.FATAL.Panicf("Failed to receive file %s: %+v", tid, err)
			}
			fmt.Printf("Completed receiving file:\n%s\n", receivedFile)
			done <- struct{}{}
		} else if err != nil {
			fmt.Printf("Failed sending file: %+v\n", err)
			done <- struct{}{}
		}
	}
}

// getContactFromFile loads the contact from the given file path.
func getContactFromFile(path string) contact.Contact {
	data, err := ioutil.ReadFile(path)
	jww.INFO.Printf("Read in contact file of size %d bytes", len(data))
	if err != nil {
		jww.FATAL.Panicf("Failed to read contact file: %+v", err)
	}

	c, err := contact.Unmarshal(data)
	if err != nil {
		jww.FATAL.Panicf("Failed to unmarshal contact: %+v", err)
	}

	return c
}

////////////////////////////////////////////////////////////////////////////////
// Command Line Flags                                                         //
////////////////////////////////////////////////////////////////////////////////

// init initializes commands and flags for Cobra.
func init() {
	ftCmd.Flags().String("sendFile", "",
		"Sends a file to a recipient with with the contact at this path.")
	bindPFlagCheckErr("sendFile")

	ftCmd.Flags().String("filePath", "testFile-"+timeNanoString()+".txt",
		"The path to the file to send. Also used as the file name.")
	bindPFlagCheckErr("filePath")

	ftCmd.Flags().String("fileType", "txt",
		"8-byte file type.")
	bindPFlagCheckErr("filePath")

	ftCmd.Flags().String("filePreviewPath", "",
		"The path to the file preview to send. Set either this flag or "+
			"filePreviewString.")
	bindPFlagCheckErr("filePreviewPath")

	ftCmd.Flags().String("filePreviewString", "",
		"File preview data. Set either this flag or filePreviewPath.")
	bindPFlagCheckErr("filePreviewString")

	ftCmd.Flags().Int("maxThroughput", 0,
		"Maximum data transfer speed to send file parts (in bytes per second)")
	bindPFlagCheckErr("maxThroughput")

	ftCmd.Flags().Float64("retry", 0.5,
		"Retry rate.")
	bindPFlagCheckErr("retry")

	rootCmd.AddCommand(ftCmd)
}

// timeNanoString returns the current UNIX time in nanoseconds as a string.
func timeNanoString() string {
	return strconv.Itoa(int(netTime.Now().UnixNano()))
}

// bindPFlagCheckErr binds the key to a pflag.Flag used by Cobra and prints an
// error if one occurs.
func bindPFlagCheckErr(key string) {
	err := viper.BindPFlag(key, ftCmd.Flags().Lookup(key))
	if err != nil {
		jww.ERROR.Printf("viper.BindPFlag failed for %q: %+v", key, err)
	}
}
