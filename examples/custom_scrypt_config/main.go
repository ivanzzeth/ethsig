package main

import (
	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Define custom scrypt parameters
	customConfig := ethsig.KeystoreScryptConfig{
		N: 1 << 18, // Custom CPU/memory cost
		P: 1,       // Custom parallelization
	}

	keystorePath := "/path/to/keystore/UTC--..."
	password := "your-password"

	_, err := ethsig.NewKeystoreSigner(
		keystorePath,
		password,
		&customConfig,
	)
	if err != nil {
		panic(err)
	}
}
