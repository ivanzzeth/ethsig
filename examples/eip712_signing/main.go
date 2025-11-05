package main

import (
	"fmt"

	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/eip712"
)

func main() {
	// Create signer (example using private key)
	privateKeyHex := "your-private-key-hex"
	signer, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(privateKeyHex)
	if err != nil {
		panic(err)
	}

	// Define typed data
	typedData := eip712.TypedData{
		Domain: eip712.TypedDataDomain{
			Name:              "MyDApp",
			Version:           "1",
			ChainId:           "1",
			VerifyingContract: "0x...",
		},
		PrimaryType: "Mail",
		Types: map[string][]eip712.Type{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "contents", Type: "string"},
			},
		},
		Message: map[string]interface{}{
			"from":     "0x1234...",
			"to":       "0x5678...",
			"contents": "Hello!",
		},
	}

	signature, err := signer.SignTypedData(typedData)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature: %x\n", signature)
}
