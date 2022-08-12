///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package main

import (
	"fmt"
	"gitlab.com/elixxir/client/cmd"
	"gitlab.com/elixxir/client/wasm"
	"runtime"
	"syscall/js"
)

// main needs no introduction.
func main() {
	// FIXME: this probably isn't the correct way to check this
	if runtime.GOOS == "js" {
		fmt.Println("Go Web Assembly")

		// wasm/cmix.go
		js.Global().Set("NewCmix", js.FuncOf(wasm.NewCmix))
		js.Global().Set("LoadCmix", js.FuncOf(wasm.LoadCmix))

		// wasm/e2e.go
		js.Global().Set("Login", js.FuncOf(wasm.Login))
		js.Global().Set("LoginEphemeral", js.FuncOf(wasm.LoginEphemeral))

		// wasm/identity.go
		js.Global().Set("StoreReceptionIdentity",
			js.FuncOf(wasm.StoreReceptionIdentity))
		js.Global().Set("LoadReceptionIdentity",
			js.FuncOf(wasm.LoadReceptionIdentity))
		js.Global().Set("GetIDFromContact",
			js.FuncOf(wasm.GetIDFromContact))
		js.Global().Set("GetPubkeyFromContact",
			js.FuncOf(wasm.GetPubkeyFromContact))
		js.Global().Set("SetFactsOnContact",
			js.FuncOf(wasm.SetFactsOnContact))
		js.Global().Set("GetFactsFromContact",
			js.FuncOf(wasm.GetFactsFromContact))
		<-make(chan bool)
	}

	cmd.Execute()
}
