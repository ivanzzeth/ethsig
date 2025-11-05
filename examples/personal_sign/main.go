package main

import (
	"fmt"

	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Create signer (example using private key)
	privateKeyHex := "your-private-key-hex"
	signer, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(privateKeyHex)
	if err != nil {
		panic(err)
	}

	// Signs with prefix: "\x19Ethereum Signed Message:\n" + len(message) + message
	message := "Sign this message"
	signature, err := signer.PersonalSign(message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %x\n", signature)
}
