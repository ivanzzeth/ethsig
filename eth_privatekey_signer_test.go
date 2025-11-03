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

// Test private key (DO NOT USE IN PRODUCTION)
// This is a test-only key composed of repeating patterns for easy identification
const testPrivateKeyHex = "1234567890123456789012345678901234567890123456789012345678901234"

func TestNewEthPrivateKeySignerFromPrivateKeyHex(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Just verify we get a valid non-zero address
	address := signer.GetAddress()
	if address == (common.Address{}) {
		t.Error("GetAddress returned zero address")
	}

	t.Logf("Test private key address: %s", address.Hex())
}

func TestGetAddress(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	address := signer.GetAddress()
	if address == (common.Address{}) {
		t.Error("GetAddress returned zero address")
	}

	// Verify it's a valid Ethereum address
	if len(address.Bytes()) != 20 {
		t.Errorf("Invalid address length: expected 20, got %d", len(address.Bytes()))
	}
}

func TestSignHash(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test hash
	hash := crypto.Keccak256Hash([]byte("test message"))

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
	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Signature validation failed")
	}
}

func TestPersonalSign(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := "Hello, Ethereum!"

	signature, err := signer.PersonalSign(message)
	if err != nil {
		t.Fatalf("PersonalSign failed: %v", err)
	}

	// Verify signature length
	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Manually construct the personal sign message for verification
	// The format is: "\x19Ethereum Signed Message:\n" + len(message) + message
	messageBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)
	hash := crypto.Keccak256Hash(prefixedMessage)

	// Verify signature
	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("PersonalSign signature validation failed")
	}
}

func TestSignEIP191Message(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test EIP-191 version 0x01 (EIP-712) message
	// Format: 0x19 <0x01> <domainSeparator (32 bytes)> <hashStruct (32 bytes)>
	domainSeparator := crypto.Keccak256Hash([]byte("domain"))
	hashStruct := crypto.Keccak256Hash([]byte("struct"))
	eip191Message := append([]byte{0x19, 0x01}, domainSeparator.Bytes()...)
	eip191Message = append(eip191Message, hashStruct.Bytes()...)

	signature, err := signer.SignEIP191Message(string(eip191Message))
	if err != nil {
		t.Fatalf("SignEIP191Message failed: %v", err)
	}

	// Verify signature length
	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}
}

func TestSignTypedData(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Get the actual address for this test key
	testAddress := signer.GetAddress()

	// Create a simple typed data structure
	typedData := eip712.TypedData{
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
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: eip712.TypedDataMessage{
			"name":   "Alice",
			"wallet": testAddress.Hex(),
		},
	}

	signature, err := signer.SignTypedData(typedData)
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
}

func TestValidateSignature(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("test message")
	hash := crypto.Keccak256Hash(message)

	signature, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("SignHash failed: %v", err)
	}

	// Test with correct address
	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Signature should be valid")
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

	// Test with wrong hash
	wrongHash := crypto.Keccak256Hash([]byte("wrong message"))
	valid, err = ValidateSignature(address, wrongHash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if valid {
		t.Error("Signature should be invalid for wrong hash")
	}
}

func TestValidateSignature_InvalidLength(t *testing.T) {
	// Use any valid address for this test since we're only testing signature length validation
	address := common.HexToAddress("0x0000000000000000000000000000000000000001")
	hash := crypto.Keccak256Hash([]byte("test"))
	invalidSig := []byte{1, 2, 3} // Too short

	_, err := ValidateSignature(address, hash, invalidSig)
	if err != ErrInvalidSignatureLen {
		t.Errorf("Expected ErrInvalidSignatureLen, got: %v", err)
	}
}

func TestSignTransaction(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create a test transaction
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	chainID := big.NewInt(1) // Ethereum mainnet

	// Create a dynamic fee transaction (EIP-1559)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1000000000), // 1 gwei
		GasFeeCap: big.NewInt(2000000000), // 2 gwei
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1000000000000000000), // 1 ETH
		Data:      nil,
	})

	// Sign the transaction with explicit chainID
	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
	if err != nil {
		t.Fatalf("SignTransactionWithChainID failed: %v", err)
	}

	// Verify the transaction is signed
	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}

	// Verify we can recover the sender address
	recoveredSigner := types.LatestSignerForChainID(chainID)
	recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
	if err != nil {
		t.Fatalf("Failed to recover sender: %v", err)
	}

	expectedAddr := signer.GetAddress()
	if recoveredAddr != expectedAddr {
		t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
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
}

func TestSignTransaction_LegacyTx(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create a legacy transaction with chainID
	to := common.HexToAddress("0x0000000000000000000000000000000000000002")
	chainID := big.NewInt(137) // Polygon

	// Create legacy tx using NewTransaction which sets chainID internally
	legacySigner := types.NewEIP155Signer(chainID)
	tx, err := types.SignNewTx(signer.privateKey, legacySigner, &types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(30000000000), // 30 gwei
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(500000000000000000), // 0.5 ETH
		Data:     nil,
	})
	if err != nil {
		t.Fatalf("Failed to sign legacy transaction: %v", err)
	}

	// Verify we can recover the sender
	recoveredAddr, err := types.Sender(legacySigner, tx)
	if err != nil {
		t.Fatalf("Failed to recover sender: %v", err)
	}

	expectedAddr := signer.GetAddress()
	if recoveredAddr != expectedAddr {
		t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}

	// Verify transaction properties
	if tx.Nonce() != 0 {
		t.Errorf("Nonce mismatch. Expected: 0, Got: %d", tx.Nonce())
	}
	if tx.To().Hex() != to.Hex() {
		t.Errorf("To address mismatch. Expected: %s, Got: %s", to.Hex(), tx.To().Hex())
	}
}

func TestSignTransaction_NilTransaction(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	chainID := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(nil, chainID)
	if err == nil {
		t.Error("Expected error for nil transaction, got none")
	}
	if err.Error() != "transaction is nil" {
		t.Errorf("Expected 'transaction is nil' error, got: %v", err)
	}
}

// Tests for flexible helper functions with any type

func TestFlexiblePersonalSign(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := "Test flexible personal sign"

	// Test with any type (should auto-detect PersonalSigner)
	signature, err := PersonalSign(signer, message)
	if err != nil {
		t.Fatalf("PersonalSign with any type failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify signature
	messageBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)
	hash := crypto.Keccak256Hash(prefixedMessage)

	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Signature validation failed")
	}
}

func TestFlexibleSignTypedData(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	testAddress := signer.GetAddress()

	typedData := eip712.TypedData{
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
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: eip712.TypedDataMessage{
			"name":   "Bob",
			"wallet": testAddress.Hex(),
		},
	}

	// Test with any type (should auto-detect TypedDataSigner)
	signature, err := SignTypedData(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedData with any type failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify V value is 27 or 28
	v := signature[64]
	if v != 27 && v != 28 {
		t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
	}
}

func TestFlexibleSignTransaction(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	to := common.HexToAddress("0x0000000000000000000000000000000000000003")
	chainID := big.NewInt(1)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     5,
		GasTipCap: big.NewInt(2000000000),
		GasFeeCap: big.NewInt(3000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(100000000000000000),
		Data:      nil,
	})

	// Test with any type (should auto-detect TransactionSigner)
	signedTx, err := SignTransaction(signer, tx, chainID)
	if err != nil {
		t.Fatalf("SignTransaction with any type failed: %v", err)
	}

	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}

	// Verify sender recovery
	recoveredSigner := types.LatestSignerForChainID(chainID)
	recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
	if err != nil {
		t.Fatalf("Failed to recover sender: %v", err)
	}

	expectedAddr := signer.GetAddress()
	if recoveredAddr != expectedAddr {
		t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}
}

func TestFlexibleGetAddress(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test with any type (should auto-detect AddressGetter)
	address, err := GetAddress(signer)
	if err != nil {
		t.Fatalf("GetAddress with any type failed: %v", err)
	}

	if address == (common.Address{}) {
		t.Error("GetAddress returned zero address")
	}

	// Should match direct call
	expectedAddr := signer.GetAddress()
	if address != expectedAddr {
		t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), address.Hex())
	}
}

// Tests for composable helper functions

func TestPersonalSignWithHash(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := "Test PersonalSignWithHash"

	// Sign using PersonalSignWithHash (HashSigner-based)
	signature, err := PersonalSignWithHash(signer, message)
	if err != nil {
		t.Fatalf("PersonalSignWithHash failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify signature
	messageBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)
	hash := crypto.Keccak256Hash(prefixedMessage)

	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Signature validation failed")
	}
}

func TestPersonalSignWithEIP191(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := "Test PersonalSignWithEIP191"

	// Sign using PersonalSignWithEIP191 (EIP191Signer-based)
	signature, err := PersonalSignWithEIP191(signer, message)
	if err != nil {
		t.Fatalf("PersonalSignWithEIP191 failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify signature
	messageBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)
	hash := crypto.Keccak256Hash(prefixedMessage)

	address := signer.GetAddress()
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Signature validation failed")
	}
}

func TestSignTypedDataWithHash(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	testAddress := signer.GetAddress()

	typedData := eip712.TypedData{
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
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: eip712.TypedDataMessage{
			"name":   "Charlie",
			"wallet": testAddress.Hex(),
		},
	}

	// Sign using SignTypedDataWithHash (HashSigner-based)
	signature, err := SignTypedDataWithHash(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedDataWithHash failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify V value is 27 or 28
	v := signature[64]
	if v != 27 && v != 28 {
		t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
	}
}

func TestSignTypedDataWithEIP191(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	testAddress := signer.GetAddress()

	typedData := eip712.TypedData{
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
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: eip712.TypedDataMessage{
			"name":   "David",
			"wallet": testAddress.Hex(),
		},
	}

	// Sign using SignTypedDataWithEIP191 (EIP191Signer-based)
	signature, err := SignTypedDataWithEIP191(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedDataWithEIP191 failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Verify V value is 27 or 28
	v := signature[64]
	if v != 27 && v != 28 {
		t.Errorf("Invalid V value: expected 27 or 28, got %d", v)
	}
}

func TestSignTransactionWithHashSigner(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	to := common.HexToAddress("0x0000000000000000000000000000000000000004")
	chainID := big.NewInt(1)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     10,
		GasTipCap: big.NewInt(1500000000),
		GasFeeCap: big.NewInt(2500000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000),
		Data:      nil,
	})

	// Sign using SignTransactionWithHashSigner (HashSigner-based)
	signedTx, err := SignTransactionWithHashSigner(signer, tx, chainID)
	if err != nil {
		t.Fatalf("SignTransactionWithHashSigner failed: %v", err)
	}

	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}

	// Verify sender recovery
	recoveredSigner := types.LatestSignerForChainID(chainID)
	recoveredAddr, err := types.Sender(recoveredSigner, signedTx)
	if err != nil {
		t.Fatalf("Failed to recover sender: %v", err)
	}

	expectedAddr := signer.GetAddress()
	if recoveredAddr != expectedAddr {
		t.Errorf("Recovered address mismatch. Expected: %s, Got: %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}

	// Verify transaction properties
	if signedTx.Nonce() != tx.Nonce() {
		t.Errorf("Nonce mismatch. Expected: %d, Got: %d", tx.Nonce(), signedTx.Nonce())
	}
}

// TestEthPrivateKeySignerWithSpecTest uses the unified SpecTest pattern to test EthPrivateKeySigner
// This ensures that EthPrivateKeySigner properly implements all interfaces
func TestEthPrivateKeySignerWithSpecTest(t *testing.T) {
	signer, err := NewEthPrivateKeySignerFromPrivateKeyHex(testPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	address := signer.GetAddress()

	// Run comprehensive SpecTest for all interfaces
	SpecTestAllInterfaces(t, signer, address)
}
