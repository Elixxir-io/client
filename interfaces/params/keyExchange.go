///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package params

import (
	"encoding/json"
	"time"
)

type Rekey struct {
	RoundTimeout time.Duration
}

func GetDefaultRekey() Rekey {
	return Rekey{
		RoundTimeout: time.Minute,
	}
}

func (r *Rekey) MarshalJSON() ([]byte, error) {
	return json.Marshal(r)
}

func (r *Rekey) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, r)
}

// Obtain default Rekey parameters, or override with given parameters if set
func GetRekeyParameters(params string) (Rekey, error) {
	p := GetDefaultRekey()
	if len(params) > 0 {
		err := p.UnmarshalJSON([]byte(params))
		if err != nil {
			return Rekey{}, err
		}
	}
	return p, nil
}
