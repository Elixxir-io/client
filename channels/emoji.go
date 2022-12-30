////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"github.com/forPelevin/gomoji"
)

// ValidateReaction checks that the reaction only contains a single emoji.
func ValidateReaction(reaction string) error {
	emojisList := gomoji.CollectAll(reaction)
	if len(emojisList) < 1 {
		return InvalidReaction
	} else if len(emojisList) > 1 {
		return InvalidReaction
	} else if emojisList[0].Character != reaction {
		return InvalidReaction
	}

	return nil
}
