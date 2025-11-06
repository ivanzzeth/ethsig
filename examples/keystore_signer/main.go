package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Example address (replace with your actual address)
	address := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create keystore signer (uses LightScryptConfig by default for testing)
	signer, err := ethsig.NewKeystoreSignerFromPath(
		"/path/to/keystore/UTC--...",
		address,
		"your-password",
		nil, // nil = use default LightScryptConfig (fast)
	)
	if err != nil {
		panic(err)
	}
	defer signer.Close()

	// For production, use StandardScryptConfig for higher security
	productionSigner, err := ethsig.NewKeystoreSignerFromPath(
		"/path/to/keystore/UTC--...",
		address,
		"your-password",
		&ethsig.StandardScryptConfig, // High security, slower
	)
	if err != nil {
		panic(err)
	}
	defer productionSigner.Close()

	fmt.Printf("Signer address: %s\n", signer.GetAddress().Hex())
}
