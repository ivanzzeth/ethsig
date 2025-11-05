package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig"
)

func main() {
	// Create signer (example using private key)
	privateKeyHex := "your-private-key-hex"
	signer, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(privateKeyHex)
	if err != nil {
		panic(err)
	}

	// Create transaction
	tx := types.NewTransaction(
		0,                                    // nonce
		common.HexToAddress("0x..."),        // to
		big.NewInt(1000000000000000000),     // value (1 ETH)
		21000,                               // gas limit
		big.NewInt(20000000000),             // gas price
		nil,                                 // data
	)

	// Sign with chain ID
	chainID := big.NewInt(1) // Ethereum mainnet
	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signed transaction hash: %s\n", signedTx.Hash().Hex())
}
