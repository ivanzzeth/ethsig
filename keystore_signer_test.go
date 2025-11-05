package ethsig

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

// Test password for keystore files
const testPassword = "testpassword123"

func TestNewKeystoreSigner(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore file
	keystorePath, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test loading the keystore
	signer, err := NewKeystoreSigner(keystorePath, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	// Verify the address matches
	address := signer.GetAddress()
	if address != expectedAddress {
		t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddress.Hex(), address.Hex())
	}

	// Verify keystore path
	if signer.GetKeystorePath() != keystorePath {
		t.Errorf("Keystore path mismatch. Expected: %s, Got: %s", keystorePath, signer.GetKeystorePath())
	}
}

func TestNewKeystoreSigner_InvalidPath(t *testing.T) {
	// Test with non-existent file
	_, err := NewKeystoreSigner("/nonexistent/path", testPassword, nil)
	if err == nil {
		t.Error("Expected error for non-existent keystore file")
	}

	// Test with empty path
	_, err = NewKeystoreSigner("", testPassword, nil)
	if err == nil {
		t.Error("Expected error for empty keystore path")
	}
}

func TestNewKeystoreSigner_WrongPassword(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore file
	keystorePath, _, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test with wrong password
	_, err = NewKeystoreSigner(keystorePath, "wrongpassword", nil)
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestNewKeystoreSignerFromDirectory(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore file
	keystorePath, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test loading from directory
	signer, err := NewKeystoreSignerFromDirectory(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore signer from directory: %v", err)
	}

	// Verify the address matches
	address := signer.GetAddress()
	if address != expectedAddress {
		t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddress.Hex(), address.Hex())
	}

	// Verify keystore path
	if signer.GetKeystorePath() != keystorePath {
		t.Errorf("Keystore path mismatch. Expected: %s, Got: %s", keystorePath, signer.GetKeystorePath())
	}
}

func TestNewKeystoreSignerFromDirectory_EmptyDirectory(t *testing.T) {
	// Create a temporary directory (empty)
	tempDir := t.TempDir()

	// Test with empty directory
	_, err := NewKeystoreSignerFromDirectory(tempDir, testPassword, nil)
	if err == nil {
		t.Error("Expected error for empty directory")
	}

	// Test with non-existent directory
	_, err = NewKeystoreSignerFromDirectory("/nonexistent/directory", testPassword, nil)
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}

	// Test with empty directory path
	_, err = NewKeystoreSignerFromDirectory("", testPassword, nil)
	if err == nil {
		t.Error("Expected error for empty directory path")
	}
}

func TestCreateKeystore(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a new keystore
	signer, keystorePath, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Verify the keystore file exists
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		t.Errorf("Keystore file does not exist: %s", keystorePath)
	}

	// Verify we can load from the created keystore
	loadedSigner, err := NewKeystoreSigner(keystorePath, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to load created keystore: %v", err)
	}

	// Verify addresses match
	originalAddress := signer.GetAddress()
	loadedAddress := loadedSigner.GetAddress()
	if originalAddress != loadedAddress {
		t.Errorf("Address mismatch. Original: %s, Loaded: %s", originalAddress.Hex(), loadedAddress.Hex())
	}

	// Verify keystore path
	if signer.GetKeystorePath() != keystorePath {
		t.Errorf("Keystore path mismatch. Expected: %s, Got: %s", keystorePath, signer.GetKeystorePath())
	}
}

func TestCreateKeystore_InvalidDirectory(t *testing.T) {
	// Test with empty directory
	_, _, err := CreateKeystore("", testPassword, nil)
	if err == nil {
		t.Error("Expected error for empty directory")
	}

	// Test with invalid directory path
	_, _, err = CreateKeystore("/invalid/path/with/permission/denied", testPassword, nil)
	if err == nil {
		t.Error("Expected error for invalid directory path")
	}
}

func TestKeystoreSigner_SignHash(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test hash signing
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

func TestKeystoreSigner_PersonalSign(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
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

func TestKeystoreSigner_SignEIP191Message(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test EIP-191 version 0x01 (EIP-712) message
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

func TestKeystoreSigner_SignTypedData(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
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

func TestKeystoreSigner_SignTransaction(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
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

func TestKeystoreSigner_ExportPrivateKey(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Export the private key should fail with current implementation
	_, err = signer.ExportPrivateKey()
	if err == nil {
		t.Error("Expected ExportPrivateKey to fail with keystore-based implementation")
	}
	
	// Verify the error message
	expectedError := "private key export not supported with keystore-based implementation"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestKeystoreSigner_InterfaceCompatibility(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test AddressGetter interface
	var addressGetter AddressGetter = signer
	address := addressGetter.GetAddress()
	if address == (common.Address{}) {
		t.Error("AddressGetter returned zero address")
	}

	// Test HashSigner interface
	var hashSigner HashSigner = signer
	hash := crypto.Keccak256Hash([]byte("test"))
	signature, err := hashSigner.SignHash(hash)
	if err != nil {
		t.Fatalf("HashSigner.SignHash failed: %v", err)
	}
	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Test EIP191Signer interface
	var eip191Signer EIP191Signer = signer
	// Create a properly formatted EIP-191 message (version 0x01 for EIP-712)
	domainSeparator := crypto.Keccak256Hash([]byte("domain"))
	hashStruct := crypto.Keccak256Hash([]byte("struct"))
	eip191Message := append([]byte{0x19, 0x01}, domainSeparator.Bytes()...)
	eip191Message = append(eip191Message, hashStruct.Bytes()...)
	eip191Signature, err := eip191Signer.SignEIP191Message(string(eip191Message))
	if err != nil {
		t.Fatalf("EIP191Signer.SignEIP191Message failed: %v", err)
	}
	if len(eip191Signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(eip191Signature))
	}

	// Test PersonalSigner interface
	var personalSigner PersonalSigner = signer
	personalSignature, err := personalSigner.PersonalSign("test")
	if err != nil {
		t.Fatalf("PersonalSigner.PersonalSign failed: %v", err)
	}
	if len(personalSignature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(personalSignature))
	}

	// Test TypedDataSigner interface
	var typedDataSigner TypedDataSigner = signer
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
	typedDataSignature, err := typedDataSigner.SignTypedData(typedData)
	if err != nil {
		t.Fatalf("TypedDataSigner.SignTypedData failed: %v", err)
	}
	if len(typedDataSignature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(typedDataSignature))
	}

	// Test TransactionSigner interface
	var transactionSigner TransactionSigner = signer
	to := common.HexToAddress("0x0000000000000000000000000000000000000002")
	chainID := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     1,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(2000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000),
		Data:      nil,
	})
	signedTx, err := transactionSigner.SignTransactionWithChainID(tx, chainID)
	if err != nil {
		t.Fatalf("TransactionSigner.SignTransactionWithChainID failed: %v", err)
	}
	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}
}

func TestKeystoreSigner_FlexibleHelpers(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test flexible PersonalSign
	message := "Test flexible personal sign"
	signature, err := PersonalSign(signer, message)
	if err != nil {
		t.Fatalf("PersonalSign with any type failed: %v", err)
	}
	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Test flexible SignTypedData
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
	typedDataSignature, err := SignTypedData(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedData with any type failed: %v", err)
	}
	if len(typedDataSignature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(typedDataSignature))
	}

	// Test flexible SignTransaction
	to := common.HexToAddress("0x0000000000000000000000000000000000000003")
	chainID := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     2,
		GasTipCap: big.NewInt(1500000000),
		GasFeeCap: big.NewInt(2500000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(100000000000000000),
		Data:      nil,
	})
	signedTx, err := SignTransaction(signer, tx, chainID)
	if err != nil {
		t.Fatalf("SignTransaction with any type failed: %v", err)
	}
	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}

	// Test flexible GetAddress
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

func TestKeystoreSigner_ComposableHelpers(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Test PersonalSignWithHash
	message := "Test PersonalSignWithHash"
	signature, err := PersonalSignWithHash(signer, message)
	if err != nil {
		t.Fatalf("PersonalSignWithHash failed: %v", err)
	}
	if len(signature) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature))
	}

	// Test PersonalSignWithEIP191
	message2 := "Test PersonalSignWithEIP191"
	signature2, err := PersonalSignWithEIP191(signer, message2)
	if err != nil {
		t.Fatalf("PersonalSignWithEIP191 failed: %v", err)
	}
	if len(signature2) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature2))
	}

	// Test SignTypedDataWithHash
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
	signature3, err := SignTypedDataWithHash(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedDataWithHash failed: %v", err)
	}
	if len(signature3) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature3))
	}

	// Test SignTypedDataWithEIP191
	signature4, err := SignTypedDataWithEIP191(signer, typedData)
	if err != nil {
		t.Fatalf("SignTypedDataWithEIP191 failed: %v", err)
	}
	if len(signature4) != 65 {
		t.Errorf("Invalid signature length: expected 65, got %d", len(signature4))
	}

	// Test SignTransactionWithHashSigner
	to := common.HexToAddress("0x0000000000000000000000000000000000000004")
	chainID := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     3,
		GasTipCap: big.NewInt(2000000000),
		GasFeeCap: big.NewInt(3000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000),
		Data:      nil,
	})
	signedTx, err := SignTransactionWithHashSigner(signer, tx, chainID)
	if err != nil {
		t.Fatalf("SignTransactionWithHashSigner failed: %v", err)
	}
	if signedTx == nil {
		t.Fatal("Signed transaction is nil")
	}
}

// TestKeystoreSignerWithSpecTest uses the unified SpecTest pattern to test KeystoreSigner
// This ensures that KeystoreSigner properly implements all interfaces
func TestKeystoreSignerWithSpecTest(t *testing.T) {
	// Create a temporary directory for keystore files
	tempDir := t.TempDir()

	// Create a test keystore and signer
	signer, _, err := CreateKeystore(tempDir, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	address := signer.GetAddress()

	// Run comprehensive SpecTest for all interfaces
	SpecTestAllInterfaces(t, signer, address)
}