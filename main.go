////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package main

import "C"

import (
	"gitlab.com/elixxir/client/v4/bindings"
	"gitlab.com/elixxir/client/v4/cmd"
)

// main needs no introduction.
func main() {
	bindings.Init()
	cmd.Execute()
}
