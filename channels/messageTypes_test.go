////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"testing"
)

// Consistency test of MessageType.String.
func TestMessageType_String_Consistency(t *testing.T) {
	expectedStrings := []string{
		"Text", "AdminText", "Reaction", "Unknown messageType 4",
		"Unknown messageType 5", "Unknown messageType 6",
		"Unknown messageType 7", "Unknown messageType 8",
		"Unknown messageType 9", "Unknown messageType 10",
	}

	for i, expected := range expectedStrings {
		mt := MessageType(i + 1)
		if mt.String() != expected {
			t.Errorf("Stringer failed on test %d.\nexpected: %s\nreceived: %s",
				i, expected, mt)
		}
	}
}

// Consistency test of MessageType.Bytes.
func TestMessageType_Bytes_Consistency(t *testing.T) {
	expectedBytes := [][]byte{{1, 0, 0, 0}, {2, 0, 0, 0}, {3, 0, 0, 0}}

	for i, expected := range expectedBytes {
		mt := MessageType(i + 1)
		if !bytes.Equal(mt.Bytes(), expected) {
			t.Errorf("Bytes failed on test %d.\nexpected: %v\nreceived: %v",
				i, expected, mt.Bytes())
		}
	}
}
