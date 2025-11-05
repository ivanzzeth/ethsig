package main

import (
	"fmt"

	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Create keystore signer (uses LightScryptConfig by default for testing)
	_, err := ethsig.NewKeystoreSigner(
		"/path/to/keystore/UTC--...",
		"your-password",
		nil, // nil = use default LightScryptConfig (fast)
	)
	if err != nil {
		panic(err)
	}

	// For production, use StandardScryptConfig for higher security
	productionSigner, err := ethsig.NewKeystoreSigner(
		"/path/to/keystore/UTC--...",
		"your-password",
		&ethsig.StandardScryptConfig, // High security, slower
	)
	if err != nil {
		panic(err)
	}
	defer productionSigner.Close()

	// Or create a new keystore
	newSigner, keystorePath, err := ethsig.CreateKeystore(
		"/path/to/keystore/dir",
		"your-password",
		nil, // nil = LightScryptConfig
	)
	if err != nil {
		panic(err)
	}
	defer newSigner.Close()
	fmt.Printf("Created keystore at: %s\n", keystorePath)
}
