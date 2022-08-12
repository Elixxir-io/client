///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

//go:build !js
// +build !js

package main

import "gitlab.com/elixxir/client/cmd"

// main needs no introduction.
func main() {
	cmd.Execute()
}
