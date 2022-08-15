////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package wasm

import (
	"syscall/js"
)

func CopyBytesToGo(src js.Value) []byte {
	b := make([]byte, src.Length())
	js.CopyBytesToGo(b, src)
	return b
}

func CopyBytesToJS(src []byte) js.Value {
	dst := js.Global().Get("Uint8Array").New(len(src))
	js.CopyBytesToJS(dst, src)
	return dst
}

// Throw function stub to throw javascript exceptions
// Without func body!
func Throw(exception Exception, message string)

type Exception string

const (
	// EvalError occurs when error has occurred in the eval() function.
	//
	// Deprecated: This exception is not thrown by JavaScript anymore, however
	// the EvalError object remains for compatibility.
	EvalError Exception = "EvalError"

	// RangeError occurs when a numeric variable or parameter is outside its
	// valid range.
	RangeError Exception = "RangeError"

	// ReferenceError occurs when a variable that does not exist (or hasn't yet
	// been initialized) in the current scope is referenced.
	ReferenceError Exception = "ReferenceError"

	// SyntaxError occurs when trying to interpret syntactically invalid code.
	SyntaxError Exception = "SyntaxError"

	// TypeError occurs when an operation could not be performed, typically (but
	// not exclusively) when a value is not of the expected type.
	//
	// A TypeError may be thrown when:
	//
	//  - an operand or argument passed to a function is incompatible with the
	//    type expected by that operator or function; or
	//  - when attempting to modify a value that cannot be changed; or
	//  - when attempting to use a value in an inappropriate way.
	TypeError Exception = "TypeError"

	// URIError occurs when a global URI handling function was used in a wrong
	// way.
	URIError Exception = "URIError"
)
