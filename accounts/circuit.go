package accounts

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// # secp256k1 signature verification circuit
//
//	Inputs: signature, msg, pubkey (public witness)
//
// verifies if the signature is valid against the message and pubkey
// msg could be hashed/direct bytes
type Secp256k1Circuit[T, S emulated.FieldParams] struct {
	Signature ecdsa.Signature[S]
	Msg       emulated.Element[S]
	Pubkey    ecdsa.PublicKey[T, S]
}

// circuit logic
func (circuit *Secp256k1Circuit[T, S]) Define(api frontend.API) error {
	//api = frontend.API(nil)
	circuit.Pubkey.Verify(api, sw_emulated.GetCurveParams[T](), &circuit.Msg, &circuit.Signature)
	return nil
}
