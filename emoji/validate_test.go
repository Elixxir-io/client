////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package emoji

import (
	"reflect"
	"testing"
)

// Unit test of SupportedEmojis.
func TestSupportedEmojis(t *testing.T) {
	emojis := SupportedEmojis()

	if len(emojis) != len(emojiMap) {
		t.Errorf("Incorrect number of emojis.\nexpected: %d\nreceived: %d",
			len(emojiMap), len(emojis))
	}
}

// Unit test of SupportedEmojisMap.
func TestSupportedEmojisMap(t *testing.T) {
	emojis := SupportedEmojisMap()

	if !reflect.DeepEqual(emojis, emojiMap) {
		t.Errorf("Incorrect map.\nexpected: %v\nreceived: %v",
			emojiMap, emojis)
	}
}

// Unit test of ValidateReaction.
func TestValidateReaction(t *testing.T) {
	tests := []struct {
		input string
		err   error
	}{
		{"😀", nil},              // Single-rune emoji (\u1F600)
		{"👋", nil},              // Single-rune emoji (\u1F44B)
		{"👱‍♂️", nil},           // Four-rune emoji (\u1F471\u200D\u2642\uFE0F)
		{"👋🏿", nil},             // Duel-rune emoji with race modification (\u1F44B\u1F3FF)
		{"😀👋", InvalidReaction}, // Two different single-rune emoji (\u1F600\u1F44B)
		{"😀😀", InvalidReaction}, // Two of the same single-rune emoji (\u1F600\u1F600)
		{"🧖 hello 🦋 world", InvalidReaction},
		{"😀 hello 😀 world", InvalidReaction},
		{"🍆", nil},
		{"😂", nil},
		{"❤", nil},
		{"🤣", nil},
		{"👍", nil},
		{"😭", nil},
		{"🙏", nil},
		{"😘", nil},
		{"🥰", nil},
		{"😍", nil},
		{"😊", nil},
		{"☺", nil},
		{"A", InvalidReaction},
		{"b", InvalidReaction},
		{"AA", InvalidReaction},
		{"1", InvalidReaction},
		{"🍆🍆", InvalidReaction},
		{"🍆A", InvalidReaction},
		{"👍👍👍", InvalidReaction},
		{"👍😘A", InvalidReaction},
		{"🧏‍♀️", nil},
		{"❤️", nil},
	}

	for i, r := range tests {
		err := ValidateReaction(r.input)

		if err != r.err {
			t.Errorf("%2d. Incorrect response for reaction %q %X."+
				"\nexpected: %s\nreceived: %s",
				i, r.input, []rune(r.input), r.err, err)
		}
	}
}
