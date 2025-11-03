package ethsig

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

// SpecTestHashSigner provides comprehensive testing for any HashSigner implementation
// This function tests all core functionality of the HashSigner interface
func SpecTestHashSigner(t *testing.T, signer HashSigner, address common.Address) {
	t.Run("SignHash", func(t *testing.T) {
		testCases := []struct {
			name     string
			message  string
			expected bool
		}{
			{"empty message", "", true},
			{"short message", "test", true},
			{"long message", "this is a longer test message for hash signing", true},
			{"special characters", "test!@#$%^&*()_+-=[]{}|;:,.<>?", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				hash := crypto.Keccak256Hash([]byte(tc.message))

				signature, err := signer.SignHash(hash)
				if err != nil {
					t.Fatalf("SignHash failed: %v", err)
				}

				// Verify signature length (65 bytes: R + S + V)
				if len(signature) != 65 {
					t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
				}

				// Verify V value is 27 or 28
				v := signature[64]
				if v != 27 && v != 28 {
					t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
				}

				// Verify signature can recover the correct address
				valid, err := ValidateSignature(address, hash, signature)
				if err != nil {
					t.Fatalf("ValidateSignature failed: %v", err)
				}
				if !valid {
					t.Error("Signature validation failed")
				}
			})
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test that signer properly handles edge cases
		// (Note: HashSigner interface doesn't have obvious error cases for SignHash)
		// This is more about ensuring the implementation doesn't panic
		hash := common.Hash{}
		_, err := signer.SignHash(hash)
		if err != nil {
			// Some implementations might reject zero hash, that's acceptable
			t.Logf("SignHash with zero hash returned error (acceptable): %v", err)
		}
	})
}

// SpecTestPersonalSigner provides comprehensive testing for any PersonalSigner implementation
func SpecTestPersonalSigner(t *testing.T, signer PersonalSigner, address common.Address) {
	t.Run("PersonalSign", func(t *testing.T) {
		testCases := []struct {
			name     string
			message  string
			expected bool
		}{
			{"empty message", "", true},
			{"simple message", "Hello, Ethereum!", true},
			{"long message", "This is a much longer test message for personal signing functionality verification", true},
			{"special characters", "Message with !@#$%^&*() symbols", true},
			{"unicode", "Hello 世界 🌍", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.PersonalSign(tc.message)
				if err != nil {
					t.Fatalf("PersonalSign failed: %v", err)
				}

				// Verify signature length
				if len(signature) != 65 {
					t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
				}

				// Manually construct the personal sign message for verification
				messageBytes := []byte(tc.message)
				prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
				prefixedMessage := append(prefix, messageBytes...)
				hash := crypto.Keccak256Hash(prefixedMessage)

				// Verify signature
				valid, err := ValidateSignature(address, hash, signature)
				if err != nil {
					t.Fatalf("ValidateSignature failed: %v", err)
				}
				if !valid {
					t.Error("PersonalSign signature validation failed")
				}
			})
		}
	})
}

// SpecTestEIP191Signer provides comprehensive testing for any EIP191Signer implementation
func SpecTestEIP191Signer(t *testing.T, signer EIP191Signer, address common.Address) {
	t.Run("SignEIP191Message", func(t *testing.T) {
		testCases := []struct {
			name    string
			message string
			shouldPass bool
		}{
			{"EIP-712 style", "\x19\x01" + string(crypto.Keccak256Hash([]byte("domain")).Bytes()) + string(crypto.Keccak256Hash([]byte("struct")).Bytes()), true},
			// Note: Our EIP191Signer implementation validates EIP-191 message prefixes
			// Simple messages without proper prefix will fail validation
			{"simple message without prefix", "test EIP-191 message", false},
			{"empty message without prefix", "", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.SignEIP191Message(tc.message)
				
				if tc.shouldPass {
					if err != nil {
						t.Fatalf("SignEIP191Message failed: %v", err)
					}

					// Verify signature length
					if len(signature) != 65 {
						t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
					}

					// For EIP-191 messages, we sign the raw message bytes
					messageBytes := []byte(tc.message)
					hash := crypto.Keccak256Hash(messageBytes)

					// Verify signature
					valid, err := ValidateSignature(address, hash, signature)
					if err != nil {
						t.Fatalf("ValidateSignature failed: %v", err)
					}
					if !valid {
						t.Error("EIP191 signature validation failed")
					}
				} else {
					// For messages that should fail, we expect an error
					if err == nil {
						t.Error("Expected SignEIP191Message to fail for message without EIP-191 prefix")
					}
				}
			})
		}
	})
}

// SpecTestTypedDataSigner provides comprehensive testing for any TypedDataSigner implementation
func SpecTestTypedDataSigner(t *testing.T, signer TypedDataSigner, address common.Address) {
	t.Run("SignTypedData", func(t *testing.T) {
		testCases := []struct {
			name      string
			typedData eip712.TypedData
		}{
			{
				"simple person",
				eip712.TypedData{
					Types: eip712.Types{
						"EIP712Domain": []eip712.Type{
							{Name: "name", Type: "string"},
							{Name: "version", Type: "string"},
							{Name: "chainId", Type: "uint256"},
						},
						"Person": []eip712.Type{
							{Name: "name", Type: "string"},
							{Name: "wallet", Type: "address"},
						},
					},
					PrimaryType: "Person",
					Domain: eip712.TypedDataDomain{
						Name:    "Test App",
						Version: "1.0.0",
						ChainId: "1",
					},
					Message: eip712.TypedDataMessage{
						"name":   "Alice",
						"wallet": address.Hex(),
					},
				},
			},
			{
				"complex data",
				eip712.TypedData{
					Types: eip712.Types{
						"EIP712Domain": []eip712.Type{
							{Name: "name", Type: "string"},
							{Name: "version", Type: "string"},
							{Name: "chainId", Type: "uint256"},
						},
						"Mail": []eip712.Type{
							{Name: "from", Type: "Person"},
							{Name: "to", Type: "Person"},
							{Name: "contents", Type: "string"},
						},
						"Person": []eip712.Type{
							{Name: "name", Type: "string"},
							{Name: "wallet", Type: "address"},
						},
					},
					PrimaryType: "Mail",
					Domain: eip712.TypedDataDomain{
						Name:    "Ether Mail",
						Version: "1",
						ChainId: "1",
					},
					Message: eip712.TypedDataMessage{
						"from": eip712.TypedDataMessage{
							"name":   "Alice",
							"wallet": address.Hex(),
						},
						"to": eip712.TypedDataMessage{
							"name":   "Bob",
							"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
						},
						"contents": "Hello, Bob!",
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.SignTypedData(tc.typedData)
				if err != nil {
					t.Fatalf("SignTypedData failed: %v", err)
				}

				// Verify signature length (65 bytes: R + S + V)
				if len(signature) != 65 {
					t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
				}

				// Verify V value is 27 or 28
				v := signature[64]
				if v != 27 && v != 28 {
					t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
				}
			})
		}
	})
}

// SpecTestTransactionSigner provides comprehensive testing for any TransactionSigner implementation
func SpecTestTransactionSigner(t *testing.T, signer TransactionSigner, address common.Address) {
	t.Run("SignTransactionWithChainID", func(t *testing.T) {
		testCases := []struct {
			name    string
			chainID *big.Int
			nonce   uint64
			to      common.Address
			value   *big.Int
		}{
			{
				"Ethereum mainnet EIP-1559",
				big.NewInt(1),
				0,
				common.HexToAddress("0x0000000000000000000000000000000000000001"),
				big.NewInt(1000000000000000000), // 1 ETH
			},
			{
				"Polygon EIP-1559",
				big.NewInt(137),
				1,
				common.HexToAddress("0x0000000000000000000000000000000000000002"),
				big.NewInt(500000000000000000), // 0.5 ETH
			},
			{
				"Arbitrum EIP-1559",
				big.NewInt(42161),
				2,
				common.HexToAddress("0x0000000000000000000000000000000000000003"),
				big.NewInt(100000000000000000), // 0.1 ETH
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create a dynamic fee transaction (EIP-1559)
				tx := types.NewTx(&types.DynamicFeeTx{
					ChainID:   tc.chainID,
					Nonce:     tc.nonce,
					GasTipCap: big.NewInt(1000000000), // 1 gwei
					GasFeeCap: big.NewInt(2000000000), // 2 gwei
					Gas:       21000,
					To:        &tc.to,
					Value:     tc.value,
					Data:      nil,
				})

				// Sign the transaction with explicit chainID
				signedTx, err := signer.SignTransactionWithChainID(tx, tc.chainID)
				if err != nil {
					t.Fatalf("SignTransactionWithChainID failed: %v", err)
				}

				// Verify the transaction is signed
				if signedTx == nil {
					t.Fatal("Signed transaction is nil")
				}

				// Verify we can recover the sender address
				recoveredSigner := types.LatestSignerForChainID(tc.chainID)
				recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
				if err != nil {
					t.Fatalf("Failed to recover sender: %v", err)
				}

				if recoveredAddr != address {
					t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", address.Hex(), recoveredAddr.Hex())
				}

				// Verify transaction properties are preserved
				if signedTx.Nonce() != tx.Nonce() {
					t.Errorf("Nonce mismatch. Expected: %d, Got: %d", tx.Nonce(), signedTx.Nonce())
				}
				if signedTx.Value().Cmp(tx.Value()) != 0 {
					t.Errorf("Value mismatch. Expected: %s, Got: %s", tx.Value().String(), signedTx.Value().String())
				}
				if signedTx.To().Hex() != tx.To().Hex() {
					t.Errorf("To address mismatch. Expected: %s, Got: %s", tx.To().Hex(), signedTx.To().Hex())
				}
			})
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test nil transaction
		_, err := signer.SignTransactionWithChainID(nil, big.NewInt(1))
		if err == nil {
			t.Error("Expected error for nil transaction")
		}

		// Test nil chainID
		to := common.HexToAddress("0x0000000000000000000000000000000000000004")
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(1), // Set chainID for transaction creation
			Nonce:     3,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(2000000000),
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(100000000000000000),
			Data:      nil,
		})
		_, err = signer.SignTransactionWithChainID(tx, nil)
		if err == nil {
			t.Error("Expected error for nil chainID")
		}
	})
}

// SpecTestAddressGetter provides comprehensive testing for any AddressGetter implementation
func SpecTestAddressGetter(t *testing.T, getter AddressGetter) {
	t.Run("GetAddress", func(t *testing.T) {
		address := getter.GetAddress()
		
		// Verify it's not a zero address
		if address == (common.Address{}) {
			t.Error("GetAddress returned zero address")
		}

		// Verify it's a valid Ethereum address (20 bytes)
		if len(address.Bytes()) != 20 {
			t.Errorf("Invalid address length: expected 20, got %d", len(address.Bytes()))
		}

		// Verify the address is checksummed or at least valid hex
		if !common.IsHexAddress(address.Hex()) {
			t.Errorf("Invalid Ethereum address format: %s", address.Hex())
		}
	})
}

// SpecTestAllInterfaces provides comprehensive testing for a signer that implements all interfaces
// This is useful for testing complete signer implementations like EthPrivateKeySigner and KeystoreSigner
func SpecTestAllInterfaces(t *testing.T, signer any, address common.Address) {
	// Test AddressGetter
	if ag, ok := signer.(AddressGetter); ok {
		t.Run("AddressGetter", func(t *testing.T) {
			SpecTestAddressGetter(t, ag)
		})
	}

	// Test HashSigner
	if hs, ok := signer.(HashSigner); ok {
		t.Run("HashSigner", func(t *testing.T) {
			SpecTestHashSigner(t, hs, address)
		})
	}

	// Test EIP191Signer
	if eip191, ok := signer.(EIP191Signer); ok {
		t.Run("EIP191Signer", func(t *testing.T) {
			SpecTestEIP191Signer(t, eip191, address)
		})
	}

	// Test PersonalSigner
	if ps, ok := signer.(PersonalSigner); ok {
		t.Run("PersonalSigner", func(t *testing.T) {
			SpecTestPersonalSigner(t, ps, address)
		})
	}

	// Test TypedDataSigner
	if tds, ok := signer.(TypedDataSigner); ok {
		t.Run("TypedDataSigner", func(t *testing.T) {
			SpecTestTypedDataSigner(t, tds, address)
		})
	}

	// Test TransactionSigner
	if ts, ok := signer.(TransactionSigner); ok {
		t.Run("TransactionSigner", func(t *testing.T) {
			SpecTestTransactionSigner(t, ts, address)
		})
	}
}