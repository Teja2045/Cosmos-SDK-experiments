package accounts

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkEcdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

func TestCircuit(t *testing.T) {
	// generate a cosmos sdk privKey from a secret phrase
	secret := "This is a very very big secret, dont share it"
	privkey := secp256k1.GenPrivKeyFromSecret([]byte(secret))

	// translate cosmos-sdk privKey to gnark privKey
	var gnarkPrivkey ecdsa.PrivateKey
	gnarkPrivkey.Scalar = *byte32(bytes.Clone(privkey.Key))

	// private key to pubkey generation
	var k big.Int
	k.SetBytes(gnarkPrivkey.Scalar[:32])
	fmt.Println(&k)
	_, g := curve.Generators()
	gnarkPrivkey.PublicKey.A.ScalarMultiplication(&g, &k)
	gnarkPubkey := gnarkPrivkey.PublicKey

	// msg to sign
	msg := []byte("message")
	hFunc := sha256.New()
	hFunc.Reset()
	// msg2 := []byte("message")

	sign, err := privkey.Sign(msg)
	if err != nil {
		panic(err)
	}

	flag, _ := gnarkPubkey.Verify(sign, msg, hFunc)
	if !flag {
		t.Errorf("can't verify signature")
	}

	var sig ecdsa.Signature
	sig.SetBytes(sign)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	dataToHash := make([]byte, len(msg))
	copy(dataToHash[:], msg[:])
	hFunc.Reset()
	hFunc.Write(dataToHash[:])
	hramBin := hFunc.Sum(nil)
	hash := ecdsa.HashToInt(hramBin)

	circuit := Secp256k1Circuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := Secp256k1Circuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Signature: gnarkEcdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pubkey: gnarkEcdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](gnarkPubkey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](gnarkPubkey.A.Y),
		},
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	// // verify with sdk pubkey
	// isVerified := pubkey.VerifySignature(msg, sign)
	// fmt.Println("normal verification:", isVerified)

	// // verify with gnark pubkey
	// isVerified, err = gnarkPubkey.Verify(sign, msg2, sha256.New())
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("gnark verification:", isVerified)

}
