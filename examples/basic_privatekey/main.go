package main

import (
	"fmt"

	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Create signer from private key
	privateKeyHex := "your-private-key-hex"
	signer, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(privateKeyHex)
	if err != nil {
		panic(err)
	}

	// Get address
	address := signer.GetAddress()
	fmt.Printf("Address: %s\n", address.Hex())

	// Sign a message
	message := "Hello, Ethereum!"
	signature, err := signer.PersonalSign(message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %x\n", signature)
}
