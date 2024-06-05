package accounts

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

func Account() {
	// generate private from a secret phrase
	secret := "This is a very very big secret, dont share it"
	privkey := secp256k1.GenPrivKeyFromSecret([]byte(secret))

	// generate gnark private key from a secret phrase
	buf := bytes.NewBuffer([]byte{})
	buf.Write([]byte(secret))
	gnarkPrivkey, err := ecdsa.GenerateKey(buf)
	if err != nil {
		panic(err)
	}

	// pubkeys
	pubkey := privkey.PubKey()
	gnarkPubkey := gnarkPrivkey.PublicKey

	// msg to sign
	msg := []byte("message")

	sign, err := privkey.Sign(msg)
	if err != nil {
		panic(err)
	}

	// verify with sdk pubkey
	isVerified := pubkey.VerifySignature(msg, sign)
	fmt.Println("normal verification:", isVerified)

	// verify with gnark pubkey
	isVerified, err = gnarkPubkey.Verify(sign, msg, sha256.New())
	if err != nil {
		panic(err)
	}
	fmt.Println("gnark verification:", isVerified)

}
