package ethsig

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestSignTransactionWithChainID_ExplicitChainID tests that explicit chainID is always used
// This is the critical test that would have caught the chainID bug
func TestSignTransactionWithChainID_ExplicitChainID(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	// Test Case 1: Legacy transaction with explicit chainID 137 (Polygon)
	t.Run("LegacyTx_ExplicitChainID", func(t *testing.T) {
		polygonChainID := big.NewInt(137)

		// Create unsigned legacy transaction
		legacyTx := types.NewTx(&types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(1000000000000000000),
			Data:     nil,
		})

		// Before signing, tx.ChainId() might return unexpected value
		txChainIDBefore := legacyTx.ChainId()
		t.Logf("Unsigned legacy tx.ChainId() = %v", txChainIDBefore)

		// Sign with explicit chainID 137
		signedTx, err := signer.SignTransactionWithChainID(legacyTx, polygonChainID)
		if err != nil {
			t.Fatalf("Failed to sign transaction: %v", err)
		}

		// Verify the transaction was signed with the correct chainID
		recoveredSigner := types.LatestSignerForChainID(polygonChainID)
		recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
		if err != nil {
			t.Fatalf("Failed to recover sender with chainID 137: %v", err)
		}

		expectedAddr := signer.GetAddress()
		if recoveredAddr != expectedAddr {
			t.Errorf("Address recovery failed with chainID 137. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
		}

		// CRITICAL: Verify that using the wrong chainID fails recovery
		wrongChainID := big.NewInt(1) // Ethereum mainnet
		wrongSigner := types.LatestSignerForChainID(wrongChainID)
		wrongRecoveredAddr, err := types.Sender(wrongSigner, signedTx)
		if err == nil && wrongRecoveredAddr == expectedAddr {
			t.Error("CRITICAL BUG: Transaction signed with chainID 137 can be recovered with chainID 1! This means chainID was not properly used during signing.")
		}

		t.Logf("✓ Transaction correctly signed with chainID 137")
		t.Logf("✓ Cannot be recovered with wrong chainID 1")
	})

	// Test Case 2: EIP-1559 transaction with explicit chainID
	t.Run("DynamicFeeTx_ExplicitChainID", func(t *testing.T) {
		polygonChainID := big.NewInt(137)

		// Create unsigned EIP-1559 transaction with correct chainID
		// NOTE: For EIP-1559 transactions, the transaction's chainID field must match
		// the signing chainID due to go-ethereum's internal validation
		dynamicTx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   polygonChainID,
			Nonce:     0,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(2000000000),
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(1000000000000000000),
			Data:      nil,
		})

		// tx.ChainId() will return 137 (from the transaction data)
		txChainID := dynamicTx.ChainId()
		if txChainID.Cmp(polygonChainID) != 0 {
			t.Fatalf("Expected tx.ChainId() to be 137, got %v", txChainID)
		}
		t.Logf("tx.ChainId() = %v", txChainID)

		// Sign with explicit chainID 137
		signedTx, err := signer.SignTransactionWithChainID(dynamicTx, polygonChainID)
		if err != nil {
			t.Fatalf("Failed to sign transaction: %v", err)
		}

		// Verify the transaction was signed with chainID 137
		recoveredSigner := types.LatestSignerForChainID(polygonChainID)
		recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
		if err != nil {
			t.Fatalf("Failed to recover sender with chainID 137: %v", err)
		}

		expectedAddr := signer.GetAddress()
		if recoveredAddr != expectedAddr {
			t.Errorf("Address recovery failed with chainID 137. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
		}

		// CRITICAL: Verify that using the wrong chainID fails recovery
		wrongChainID := big.NewInt(1) // Ethereum mainnet
		wrongSigner := types.LatestSignerForChainID(wrongChainID)
		wrongRecoveredAddr, err := types.Sender(wrongSigner, signedTx)
		if err == nil && wrongRecoveredAddr == expectedAddr {
			t.Error("CRITICAL BUG: Transaction signed with chainID 137 can be recovered with chainID 1!")
		}

		t.Logf("✓ Transaction correctly signed with explicit chainID 137")
		t.Logf("✓ Cannot be recovered with wrong chainID 1")
	})

	// Test Case 3: Verify SignTransactionWithHashSigner uses explicit chainID
	t.Run("SignTransactionWithHashSigner_ExplicitChainID", func(t *testing.T) {
		polygonChainID := big.NewInt(137)

		legacyTx := types.NewTx(&types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(1000000000000000000),
			Data:     nil,
		})

		// Sign using SignTransactionWithHashSigner (uses HashSigner interface)
		signedTx, err := SignTransactionWithHashSigner(signer, legacyTx, polygonChainID)
		if err != nil {
			t.Fatalf("Failed to sign transaction: %v", err)
		}

		// Verify recovery with correct chainID
		recoveredSigner := types.LatestSignerForChainID(polygonChainID)
		recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
		if err != nil {
			t.Fatalf("Failed to recover sender: %v", err)
		}

		expectedAddr := signer.GetAddress()
		if recoveredAddr != expectedAddr {
			t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
		}

		t.Logf("✓ SignTransactionWithHashSigner correctly uses explicit chainID")
	})
}

// TestNewBindSignerFn tests the bind.SignerFn creation from TransactionSigner
func TestNewBindSignerFn(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	chainID := big.NewInt(137) // Polygon
	signerAddr := signer.GetAddress()

	// Test Case 1: Create bind.SignerFn from TransactionSigner
	t.Run("CreateBindSignerFn", func(t *testing.T) {
		signerFn, err := NewBindSignerFn(signer, chainID)
		if err != nil {
			t.Fatalf("Failed to create bind.SignerFn: %v", err)
		}

		if signerFn == nil {
			t.Fatal("bind.SignerFn is nil")
		}

		t.Logf("✓ Successfully created bind.SignerFn")
	})

	// Test Case 2: Use bind.SignerFn in TransactOpts
	t.Run("UseInTransactOpts", func(t *testing.T) {
		signerFn, err := NewBindSignerFn(signer, chainID)
		if err != nil {
			t.Fatalf("Failed to create bind.SignerFn: %v", err)
		}

		// Create TransactOpts
		opts := &bind.TransactOpts{
			From:   signerAddr,
			Signer: signerFn,
		}

		if opts.Signer == nil {
			t.Fatal("TransactOpts.Signer is nil")
		}

		t.Logf("✓ Successfully set bind.SignerFn in TransactOpts")
	})

	// Test Case 3: Verify bind.SignerFn signs correctly with explicit chainID
	t.Run("SignWithBindSignerFn", func(t *testing.T) {
		signerFn, err := NewBindSignerFn(signer, chainID)
		if err != nil {
			t.Fatalf("Failed to create bind.SignerFn: %v", err)
		}

		// Create a test transaction
		to := common.HexToAddress("0x0000000000000000000000000000000000000001")
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(1000000000000000000),
			Data:     nil,
		})

		// Sign using bind.SignerFn
		signedTx, err := signerFn(signerAddr, tx)
		if err != nil {
			t.Fatalf("bind.SignerFn failed to sign: %v", err)
		}

		// Verify signature with correct chainID
		recoveredSigner := types.LatestSignerForChainID(chainID)
		recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
		if err != nil {
			t.Fatalf("Failed to recover sender: %v", err)
		}

		if recoveredAddr != signerAddr {
			t.Errorf("Address mismatch. Expected: %s, Got: %s", signerAddr.Hex(), recoveredAddr.Hex())
		}

		t.Logf("✓ bind.SignerFn correctly signed transaction with chainID %d", chainID.Int64())
	})

	// Test Case 4: Verify bind.SignerFn rejects wrong address
	t.Run("RejectWrongAddress", func(t *testing.T) {
		signerFn, err := NewBindSignerFn(signer, chainID)
		if err != nil {
			t.Fatalf("Failed to create bind.SignerFn: %v", err)
		}

		wrongAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")
		to := common.HexToAddress("0x0000000000000000000000000000000000000002")
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(1000000000000000000),
			Data:     nil,
		})

		// Try to sign with wrong address
		_, err = signerFn(wrongAddr, tx)
		if err == nil {
			t.Error("Expected error when signing for wrong address, got nil")
		}

		t.Logf("✓ bind.SignerFn correctly rejected wrong address: %v", err)
	})

	// Test Case 5: Verify chainID is captured correctly in closure
	t.Run("ChainIDClosureCapture", func(t *testing.T) {
		// Create signers with different chainIDs
		polygonSignerFn, err := NewBindSignerFn(signer, big.NewInt(137))
		if err != nil {
			t.Fatalf("Failed to create Polygon signerFn: %v", err)
		}

		ethereumSignerFn, err := NewBindSignerFn(signer, big.NewInt(1))
		if err != nil {
			t.Fatalf("Failed to create Ethereum signerFn: %v", err)
		}

		to := common.HexToAddress("0x0000000000000000000000000000000000000001")
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(30000000000),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(1000000000000000000),
			Data:     nil,
		})

		// Sign with Polygon signer
		polygonSignedTx, err := polygonSignerFn(signerAddr, tx)
		if err != nil {
			t.Fatalf("Polygon signerFn failed: %v", err)
		}

		// Sign with Ethereum signer
		ethereumSignedTx, err := ethereumSignerFn(signerAddr, tx)
		if err != nil {
			t.Fatalf("Ethereum signerFn failed: %v", err)
		}

		// Verify Polygon signature works with chainID 137
		polygonSigner := types.LatestSignerForChainID(big.NewInt(137))
		polygonAddr, err := types.Sender(polygonSigner, polygonSignedTx)
		if err != nil || polygonAddr != signerAddr {
			t.Errorf("Polygon signature verification failed")
		}

		// Verify Ethereum signature works with chainID 1
		ethereumSigner := types.LatestSignerForChainID(big.NewInt(1))
		ethereumAddr, err := types.Sender(ethereumSigner, ethereumSignedTx)
		if err != nil || ethereumAddr != signerAddr {
			t.Errorf("Ethereum signature verification failed")
		}

		// Verify cross-chain verification fails
		_, err = types.Sender(polygonSigner, ethereumSignedTx)
		if err == nil {
			wrongAddr, _ := types.Sender(polygonSigner, ethereumSignedTx)
			if wrongAddr == signerAddr {
				t.Error("CRITICAL: Ethereum signature (chainID 1) verified with Polygon signer (chainID 137)")
			}
		}

		t.Logf("✓ ChainID correctly captured in closure for each signer")
	})
}

// TestNewBindSignerFn_ErrorCases tests error handling
func TestNewBindSignerFn_ErrorCases(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	t.Run("NilChainID", func(t *testing.T) {
		_, err := NewBindSignerFn(signer, nil)
		if err == nil {
			t.Error("Expected error for nil chainID, got nil")
		}
		t.Logf("✓ Correctly rejected nil chainID: %v", err)
	})

	t.Run("SignerWithoutAddressGetter", func(t *testing.T) {
		// Create a mock signer that doesn't implement AddressGetter
		type FakeSigner struct{}
		fakeSigner := FakeSigner{}

		_, err := NewBindSignerFn(fakeSigner, big.NewInt(1))
		if err == nil {
			t.Error("Expected error for signer without AddressGetter, got nil")
		}
		t.Logf("✓ Correctly rejected signer without AddressGetter: %v", err)
	})

	t.Run("NilTransaction", func(t *testing.T) {
		signerFn, err := NewBindSignerFn(signer, big.NewInt(137))
		if err != nil {
			t.Fatalf("Failed to create signerFn: %v", err)
		}

		_, err = signerFn(signer.GetAddress(), nil)
		if err == nil {
			t.Error("Expected error for nil transaction, got nil")
		}
		t.Logf("✓ Correctly rejected nil transaction: %v", err)
	})
}

// TestSignTransaction_ChainIDValidation tests chainID validation
func TestSignTransaction_ChainIDValidation(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(30000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1000000000000000000),
		Data:     nil,
	})

	t.Run("NilChainID", func(t *testing.T) {
		_, err := SignTransaction(signer, tx, nil)
		if err == nil {
			t.Error("Expected error for nil chainID, got nil")
		}
		t.Logf("✓ Correctly rejected nil chainID: %v", err)
	})

	t.Run("ValidChainID", func(t *testing.T) {
		signedTx, err := SignTransaction(signer, tx, big.NewInt(137))
		if err != nil {
			t.Fatalf("Failed to sign with valid chainID: %v", err)
		}
		if signedTx == nil {
			t.Error("Signed transaction is nil")
		}
		t.Logf("✓ Successfully signed with valid chainID")
	})
}
