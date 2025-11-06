package main

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Define custom scrypt parameters
	customConfig := ethsig.KeystoreScryptConfig{
		N: 1 << 18, // Custom CPU/memory cost
		P: 1,       // Custom parallelization
	}

	keystorePath := "/path/to/keystore/UTC--..."
	address := common.HexToAddress("0x1234567890123456789012345678901234567890")
	password := "your-password"

	signer, err := ethsig.NewKeystoreSignerFromPath(
		keystorePath,
		address,
		password,
		&customConfig,
	)
	if err != nil {
		panic(err)
	}
	defer signer.Close()
}
