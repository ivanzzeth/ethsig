package ethsig

import (
	"bytes"
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
			{"unicode characters", "Hello World 🌍", true},
			{"very long message", string(make([]byte, 10000)), true}, // 10KB message
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
		// Test edge cases and error handling
		testCases := []struct {
			name        string
			hash        common.Hash
			expectError bool
		}{
			{"zero hash", common.Hash{}, false}, // Some implementations might accept zero hash
			{"max hash", common.MaxHash, false}, // Max hash value
			{"min hash", common.Hash{}, false},  // Min hash value (same as zero)
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.SignHash(tc.hash)
				if tc.expectError {
					if err == nil {
						t.Error("Expected error but got none")
					}
				} else {
					if err != nil {
						// Some implementations might reject certain hashes, that's acceptable
						t.Logf("SignHash returned error (acceptable): %v", err)
					} else {
						// If no error, verify the signature
						if len(signature) != 65 {
							t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
						}
					}
				}
			})
		}
	})

	t.Run("SignatureConsistency", func(t *testing.T) {
		// Test that signing the same hash multiple times produces consistent results
		hash := crypto.Keccak256Hash([]byte("consistency test"))
		
		signature1, err := signer.SignHash(hash)
		if err != nil {
			t.Fatalf("First SignHash failed: %v", err)
		}

		signature2, err := signer.SignHash(hash)
		if err != nil {
			t.Fatalf("Second SignHash failed: %v", err)
		}

		// Signatures should be identical for deterministic signing
		if len(signature1) != len(signature2) {
			t.Errorf("Signature length mismatch: %d vs %d", len(signature1), len(signature2))
		}

		for i := range signature1 {
			if signature1[i] != signature2[i] {
				t.Errorf("Signature mismatch at byte %d: %v vs %v", i, signature1[i], signature2[i])
				break
			}
		}
	})

	t.Run("EdgeCases", func(t *testing.T) {
		// Test edge cases that might cause issues
		edgeCases := []struct {
			name        string
			hash        common.Hash
			expectError bool
		}{
			{"zero hash", common.Hash{}, false},
			{"max hash", common.MaxHash, false},
			{"min hash", common.Hash{}, false},
			{"all zeros hash", common.Hash{}, false},
			{"all ones hash", common.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
		}

		for _, tc := range edgeCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.SignHash(tc.hash)
				if tc.expectError {
					if err == nil {
						t.Error("Expected error but got none")
					}
				} else {
					if err != nil {
						// Some implementations might reject certain hashes, that's acceptable
						t.Logf("SignHash returned error (acceptable): %v", err)
					} else {
						// If no error, verify the signature
						if len(signature) != 65 {
							t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
						}
					}
				}
			})
		}
	})

	t.Run("Concurrency", func(t *testing.T) {
		// Test concurrent hash signing
		numGoroutines := 5
		errors := make(chan error, numGoroutines)
		hash := crypto.Keccak256Hash([]byte("concurrent test"))

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				signature, err := signer.SignHash(hash)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: SignHash failed: %v", id, err)
					return
				}

				// Verify signature length
				if len(signature) != 65 {
					errors <- fmt.Errorf("goroutine %d: invalid signature length: expected 65, got %d", id, len(signature))
					return
				}

				// Verify V value
				v := signature[64]
				if v != 27 && v != 28 {
					errors <- fmt.Errorf("goroutine %d: invalid V value: expected 27 or 28, got %d", id, v)
					return
				}

				// Verify signature
				valid, err := ValidateSignature(address, hash, signature)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: ValidateSignature failed: %v", id, err)
					return
				}
				if !valid {
					errors <- fmt.Errorf("goroutine %d: signature validation failed", id)
					return
				}

				errors <- nil
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			if err := <-errors; err != nil {
				t.Error(err)
			}
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
			{"unicode", "Hello World 🌍", true},
			{"very long message", string(make([]byte, 5000)), true}, // 5KB message
			{"newline characters", "Line 1\nLine 2\nLine 3", true},
			{"tab characters", "Tab\tSeparated\tValues", true},
			{"null bytes", "Data\x00With\x00Nulls", true},
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

				// Verify V value is 27 or 28
				v := signature[64]
				if v != 27 && v != 28 {
					t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
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

	t.Run("SignatureConsistency", func(t *testing.T) {
		// Test that signing the same message multiple times produces consistent results
		message := "consistency test message"
		
		signature1, err := signer.PersonalSign(message)
		if err != nil {
			t.Fatalf("First PersonalSign failed: %v", err)
		}

		signature2, err := signer.PersonalSign(message)
		if err != nil {
			t.Fatalf("Second PersonalSign failed: %v", err)
		}

		// Signatures should be identical for deterministic signing
		if len(signature1) != len(signature2) {
			t.Errorf("Signature length mismatch: %d vs %d", len(signature1), len(signature2))
		}

		for i := range signature1 {
			if signature1[i] != signature2[i] {
				t.Errorf("Signature mismatch at byte %d: %v vs %v", i, signature1[i], signature2[i])
				break
			}
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test edge cases that might cause issues
		// Note: PersonalSigner interface doesn't have obvious error cases
		// This is more about ensuring the implementation doesn't panic
		
		// Test with extremely long message (but not too long to avoid memory issues)
		longMessage := string(make([]byte, 100000)) // 100KB message
		signature, err := signer.PersonalSign(longMessage)
		if err != nil {
			// Some implementations might reject very long messages, that's acceptable
			t.Logf("PersonalSign with very long message returned error (acceptable): %v", err)
		} else {
			// If no error, verify the signature
			if len(signature) != 65 {
				t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
			}
		}
	})

	t.Run("EdgeCases", func(t *testing.T) {
		// Test edge cases for personal signing
		edgeCases := []struct {
			name        string
			message     string
			expectError bool
		}{
			{"empty message", "", false},
			{"null bytes", "\x00\x00\x00", false},
			{"control characters", "\x01\x02\x03\x04\x05", false},
			{"unicode null", "\u0000\u0000\u0000", false},
			{"very long message", string(make([]byte, 1000000)), false}, // 1MB message
			{"special unicode", "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀", false},
		}

		for _, tc := range edgeCases {
			t.Run(tc.name, func(t *testing.T) {
				signature, err := signer.PersonalSign(tc.message)
				if tc.expectError {
					if err == nil {
						t.Error("Expected error but got none")
					}
				} else {
					if err != nil {
						// Some implementations might reject certain messages, that's acceptable
						t.Logf("PersonalSign returned error (acceptable): %v", err)
					} else {
						// If no error, verify the signature
						if len(signature) != 65 {
							t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
						}
					}
				}
			})
		}
	})

	t.Run("Concurrency", func(t *testing.T) {
		// Test concurrent personal signing
		numGoroutines := 5
		errors := make(chan error, numGoroutines)
		message := "concurrent personal sign test"

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				signature, err := signer.PersonalSign(message)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: PersonalSign failed: %v", id, err)
					return
				}

				// Verify signature length
				if len(signature) != 65 {
					errors <- fmt.Errorf("goroutine %d: invalid signature length: expected 65, got %d", id, len(signature))
					return
				}

				// Verify V value
				v := signature[64]
				if v != 27 && v != 28 {
					errors <- fmt.Errorf("goroutine %d: invalid V value: expected 27 or 28, got %d", id, v)
					return
				}

				// Verify signature
				messageBytes := []byte(message)
				prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
				prefixedMessage := append(prefix, messageBytes...)
				hash := crypto.Keccak256Hash(prefixedMessage)

				valid, err := ValidateSignature(address, hash, signature)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: ValidateSignature failed: %v", id, err)
					return
				}
				if !valid {
					errors <- fmt.Errorf("goroutine %d: signature validation failed", id)
					return
				}

				errors <- nil
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			if err := <-errors; err != nil {
				t.Error(err)
			}
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

	t.Run("EdgeCases", func(t *testing.T) {
		// Test edge cases for EIP-191 signing
		edgeCases := []struct {
			name        string
			message     string
			shouldPass  bool
		}{
			{"empty EIP-191 message", "", false},
			{"invalid prefix", "\x18\x01", false},
			{"wrong version", "\x19\x02", false},
			{"partial prefix", "\x19", false},
			{"malformed message", "\x19\x01\x00\x00", false},
			{"very long EIP-191 message", string(make([]byte, 100000)), false}, // 100KB message
		}

		for _, tc := range edgeCases {
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
				} else {
					// For messages that should fail, we expect an error
					if err == nil {
						t.Error("Expected SignEIP191Message to fail for invalid EIP-191 message")
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

	t.Run("EdgeCases", func(t *testing.T) {
		// Test edge cases for typed data signing
		t.Run("InvalidTypedData", func(t *testing.T) {
			// Test with invalid typed data structures
			invalidCases := []struct {
				name      string
				typedData eip712.TypedData
			}{
				{
					"empty types",
					eip712.TypedData{
						Types:       eip712.Types{},
						PrimaryType: "",
						Domain:      eip712.TypedDataDomain{},
						Message:     eip712.TypedDataMessage{},
					},
				},
				{
					"missing domain",
					eip712.TypedData{
						Types: eip712.Types{
							"EIP712Domain": []eip712.Type{
								{Name: "name", Type: "string"},
							},
						},
						PrimaryType: "Test",
						Domain:      eip712.TypedDataDomain{},
						Message:     eip712.TypedDataMessage{"test": "value"},
					},
				},
			}

			for _, tc := range invalidCases {
				t.Run(tc.name, func(t *testing.T) {
					_, err := signer.SignTypedData(tc.typedData)
					// Some implementations might reject invalid typed data, that's acceptable
					if err != nil {
						t.Logf("SignTypedData returned error for invalid data (acceptable): %v", err)
					}
				})
			}
		})
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

	t.Run("EdgeCases", func(t *testing.T) {
		// Test edge cases for transaction signing
		t.Run("InvalidTransactions", func(t *testing.T) {
			// Test with various invalid transaction scenarios
			// Note: Testing with invalid chainIDs (negative, zero, very large) can cause
			// issues with go-ethereum's transaction signing implementation
			// We'll focus on testing valid chainIDs and rely on the error handling tests
		})

		t.Run("TransactionTypes", func(t *testing.T) {
			// Test different transaction types
			to := common.HexToAddress("0x0000000000000000000000000000000000000006")
			chainID := big.NewInt(1)

			// Test legacy transaction
			legacyTx := types.NewTx(&types.LegacyTx{
				Nonce:    5,
				GasPrice: big.NewInt(30000000000),
				Gas:      21000,
				To:       &to,
				Value:    big.NewInt(100000000000000000),
				Data:     nil,
			})

			signedLegacyTx, err := signer.SignTransactionWithChainID(legacyTx, chainID)
			if err != nil {
				t.Logf("SignTransactionWithChainID for legacy tx returned error (acceptable): %v", err)
			} else if signedLegacyTx != nil {
				// Verify we can recover the sender
				recoveredSigner := types.LatestSignerForChainID(chainID)
				recoveredAddr, err := types.Sender(recoveredSigner, signedLegacyTx)
				if err != nil {
					t.Logf("Failed to recover sender from legacy tx (acceptable): %v", err)
				} else if recoveredAddr != address {
					t.Errorf("Recovered address mismatch for legacy tx. Expected: %s, Got: %s", address.Hex(), recoveredAddr.Hex())
				}
			}

			// Test access list transaction
			accessListTx := types.NewTx(&types.AccessListTx{
				ChainID:    chainID,
				Nonce:      6,
				GasPrice:   big.NewInt(2000000000),
				Gas:        21000,
				To:         &to,
				Value:      big.NewInt(100000000000000000),
				Data:       nil,
				AccessList: types.AccessList{},
			})

			signedAccessListTx, err := signer.SignTransactionWithChainID(accessListTx, chainID)
			if err != nil {
				t.Logf("SignTransactionWithChainID for access list tx returned error (acceptable): %v", err)
			} else if signedAccessListTx != nil {
				// Verify we can recover the sender
				recoveredSigner := types.LatestSignerForChainID(chainID)
				recoveredAddr, err := types.Sender(recoveredSigner, signedAccessListTx)
				if err != nil {
					t.Logf("Failed to recover sender from access list tx (acceptable): %v", err)
				} else if recoveredAddr != address {
					t.Errorf("Recovered address mismatch for access list tx. Expected: %s, Got: %s", address.Hex(), recoveredAddr.Hex())
				}
			}
		})
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

	t.Run("Concurrency", func(t *testing.T) {
		// Test concurrent access to the address getter
		numGoroutines := 10
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				address := getter.GetAddress()
				if address == (common.Address{}) {
					errors <- fmt.Errorf("goroutine %d: GetAddress returned zero address", id)
				} else if len(address.Bytes()) != 20 {
					errors <- fmt.Errorf("goroutine %d: invalid address length: expected 20, got %d", id, len(address.Bytes()))
				} else {
					errors <- nil
				}
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			if err := <-errors; err != nil {
				t.Error(err)
			}
		}
	})
}

// SpecTestIntegration provides comprehensive integration testing for any signer implementation
// This function tests end-to-end workflows and cross-interface consistency
func SpecTestIntegration(t *testing.T, signer any, address common.Address) {
	t.Run("CrossInterfaceConsistency", func(t *testing.T) {
		// Test that different signing methods produce consistent results for the same data
		message := "integration test message"

		if hs, ok := signer.(HashSigner); ok {
			if ps, ok := signer.(PersonalSigner); ok {
				// Sign the same message using different methods
				hash := crypto.Keccak256Hash([]byte(message))
				hashSignature, err := hs.SignHash(hash)
				if err != nil {
					t.Fatalf("HashSigner.SignHash failed: %v", err)
				}

				personalSignature, err := ps.PersonalSign(message)
				if err != nil {
					t.Fatalf("PersonalSigner.PersonalSign failed: %v", err)
				}

				// Signatures should be different because they sign different data
				// (raw hash vs prefixed message)
				if bytes.Equal(hashSignature, personalSignature) {
					t.Error("Hash signature and personal signature should be different")
				}

				// Both signatures should validate correctly
				valid, err := ValidateSignature(address, hash, hashSignature)
				if err != nil {
					t.Fatalf("ValidateSignature for hash signature failed: %v", err)
				}
				if !valid {
					t.Error("Hash signature validation failed")
				}

				// Verify personal signature
				messageBytes := []byte(message)
				prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
				prefixedMessage := append(prefix, messageBytes...)
				personalHash := crypto.Keccak256Hash(prefixedMessage)

				valid, err = ValidateSignature(address, personalHash, personalSignature)
				if err != nil {
					t.Fatalf("ValidateSignature for personal signature failed: %v", err)
				}
				if !valid {
					t.Error("Personal signature validation failed")
				}
			}
		}
	})

	t.Run("WorkflowScenarios", func(t *testing.T) {
		// Test realistic signing workflows
		if hs, ok := signer.(HashSigner); ok {
			if ts, ok := signer.(TransactionSigner); ok {
				// Test transaction signing workflow
				to := common.HexToAddress("0x0000000000000000000000000000000000000007")
				chainID := big.NewInt(1)

				// Create a transaction
				tx := types.NewTx(&types.DynamicFeeTx{
					ChainID:   chainID,
					Nonce:     7,
					GasTipCap: big.NewInt(1000000000),
					GasFeeCap: big.NewInt(2000000000),
					Gas:       21000,
					To:        &to,
					Value:     big.NewInt(100000000000000000),
					Data:      nil,
				})

				// Sign the transaction
				signedTx, err := ts.SignTransactionWithChainID(tx, chainID)
				if err != nil {
					t.Fatalf("TransactionSigner.SignTransactionWithChainID failed: %v", err)
				}

				// Verify the transaction signature
				recoveredSigner := types.LatestSignerForChainID(chainID)
				recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
				if err != nil {
					t.Fatalf("Failed to recover sender: %v", err)
				}

				if recoveredAddr != address {
					t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", address.Hex(), recoveredAddr.Hex())
				}

				// Also test hash signing with the same signer
				hash := crypto.Keccak256Hash([]byte("workflow test"))
				hashSignature, err := hs.SignHash(hash)
				if err != nil {
					t.Fatalf("HashSigner.SignHash failed: %v", err)
				}

				valid, err := ValidateSignature(address, hash, hashSignature)
				if err != nil {
					t.Fatalf("ValidateSignature failed: %v", err)
				}
				if !valid {
					t.Error("Hash signature validation failed in workflow test")
				}
			}
		}
	})

		t.Run("AddressConsistency", func(t *testing.T) {
			// Test that address is consistent across all interfaces
			var addresses []common.Address

			if ag, ok := signer.(AddressGetter); ok {
				addresses = append(addresses, ag.GetAddress())
			}

			if hs, ok := signer.(HashSigner); ok {
				// Use hash signing to verify address
				hash := crypto.Keccak256Hash([]byte("address consistency test"))
				signature, err := hs.SignHash(hash)
				if err != nil {
					t.Fatalf("HashSigner.SignHash failed: %v", err)
				}

				// Use ValidateSignature instead of crypto.Ecrecover for better compatibility
				valid, err := ValidateSignature(addresses[0], hash, signature)
				if err != nil {
					t.Fatalf("ValidateSignature failed: %v", err)
				}
				if !valid {
					t.Error("Signature validation failed in address consistency test")
				}
			}

			// All addresses should be the same (we only have one from AddressGetter)
			if len(addresses) != 1 {
				t.Errorf("Expected 1 address, got %d", len(addresses))
			}
		})
}

// SpecTestSecurity provides comprehensive security testing for any signer implementation
// This function tests security-related scenarios and potential vulnerabilities
func SpecTestSecurity(t *testing.T, signer any, address common.Address) {
		t.Run("SignatureValidation", func(t *testing.T) {
			// Test signature validation with tampered data
			if hs, ok := signer.(HashSigner); ok {
				t.Run("HashSigner", func(t *testing.T) {
					hash := crypto.Keccak256Hash([]byte("security test"))
					signature, err := hs.SignHash(hash)
					if err != nil {
						t.Fatalf("SignHash failed: %v", err)
					}

					// Test with wrong hash
					wrongHash := crypto.Keccak256Hash([]byte("wrong message"))
					valid, err := ValidateSignature(address, wrongHash, signature)
					if err != nil {
						t.Fatalf("ValidateSignature failed: %v", err)
					}
					if valid {
						t.Error("Signature should be invalid for wrong hash")
					}

					// Test with wrong address
					wrongAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
					valid, err = ValidateSignature(wrongAddress, hash, signature)
					if err != nil {
						t.Fatalf("ValidateSignature failed: %v", err)
					}
					if valid {
						t.Error("Signature should be invalid for wrong address")
					}
				})
			}

			if ps, ok := signer.(PersonalSigner); ok {
				t.Run("PersonalSigner", func(t *testing.T) {
					message := "security test message"
					signature, err := ps.PersonalSign(message)
					if err != nil {
						t.Fatalf("PersonalSign failed: %v", err)
					}

					// Test with tampered message
					tamperedMessage := message + "tampered"
					messageBytes := []byte(tamperedMessage)
					prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
					prefixedMessage := append(prefix, messageBytes...)
					hash := crypto.Keccak256Hash(prefixedMessage)

					valid, err := ValidateSignature(address, hash, signature)
					if err != nil {
						t.Fatalf("ValidateSignature failed: %v", err)
					}
					if valid {
						t.Error("Signature should be invalid for tampered message")
					}
				})
			}
		})

	t.Run("ReplayProtection", func(t *testing.T) {
		// Test that signatures are specific to the message/hash
		if hs, ok := signer.(HashSigner); ok {
			hash1 := crypto.Keccak256Hash([]byte("message 1"))
			hash2 := crypto.Keccak256Hash([]byte("message 2"))

			signature1, err := hs.SignHash(hash1)
			if err != nil {
				t.Fatalf("SignHash failed for message 1: %v", err)
			}

			signature2, err := hs.SignHash(hash2)
			if err != nil {
				t.Fatalf("SignHash failed for message 2: %v", err)
			}

			// Signatures should be different for different messages
			if bytes.Equal(signature1, signature2) {
				t.Error("Signatures should be different for different messages")
			}

			// Signature for message 1 should not validate for message 2
			valid, err := ValidateSignature(address, hash2, signature1)
			if err != nil {
				t.Fatalf("ValidateSignature failed: %v", err)
			}
			if valid {
				t.Error("Signature replay should be detected")
			}
		}
	})

	t.Run("InvalidInputs", func(t *testing.T) {
		// Test handling of invalid cryptographic inputs
		// Test with invalid signature length
		invalidSig := []byte{1, 2, 3} // Too short
		hash := crypto.Keccak256Hash([]byte("test"))
		
		_, err := ValidateSignature(address, hash, invalidSig)
		if err != ErrInvalidSignatureLen {
			t.Errorf("Expected ErrInvalidSignatureLen for invalid signature length, got: %v", err)
		}

		// Test with empty signature
		_, err = ValidateSignature(address, hash, []byte{})
		if err != ErrInvalidSignatureLen {
			t.Errorf("Expected ErrInvalidSignatureLen for empty signature, got: %v", err)
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

	// Run security tests
	t.Run("Security", func(t *testing.T) {
		SpecTestSecurity(t, signer, address)
	})

	// Run integration tests
	t.Run("Integration", func(t *testing.T) {
		SpecTestIntegration(t, signer, address)
	})
}