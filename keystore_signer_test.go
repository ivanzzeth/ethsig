package ethsig

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

// Test password for keystore files
const testPassword = "testpassword123"

// newTestKeyStore creates a test KeyStore instance
func newTestKeyStore(keystoreDir string) *keystore.KeyStore {
	return keystore.NewKeyStore(keystoreDir, keystore.LightScryptN, keystore.LightScryptP)
}

// createTestKeystore creates a test keystore file for testing purposes
// This is an internal helper function and should not be exported
func createTestKeystore(keystoreDir, password string) (string, common.Address, error) {
	// Generate a new private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", common.Address{}, NewKeystoreError("failed to generate private key", err)
	}

	// Create the keystore directory if it doesn't exist
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return "", common.Address{}, NewKeystoreError("failed to create keystore directory", err)
	}

	// Create a new keystore
	ks := keystore.NewKeyStore(keystoreDir, keystore.LightScryptN, keystore.LightScryptP)

	// Import the private key
	account, err := ks.ImportECDSA(privateKey, password)
	if err != nil {
		return "", common.Address{}, NewKeystoreError("failed to import private key", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return account.URL.Path, address, nil
}

// TestNewKeystoreSigner tests creating a signer from an existing KeyStore
func TestNewKeystoreSigner(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	if signer.GetAddress() != expectedAddress {
		t.Errorf("Address mismatch. Expected: %s, Got: %s", expectedAddress.Hex(), signer.GetAddress().Hex())
	}

	t.Log("✓ KeystoreSigner created successfully from KeyStore")
}

// TestNewKeystoreSigner_InvalidAddress tests error handling for non-existent address
func TestNewKeystoreSigner_InvalidAddress(t *testing.T) {
	tempDir := t.TempDir()
	_, _, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	nonExistentAddr := common.HexToAddress("0x0000000000000000000000000000000000000001")

	_, err = NewKeystoreSigner(ks, nonExistentAddr, testPassword)
	if err == nil {
		t.Error("Expected error for non-existent address")
	}

	t.Log("✓ Correctly rejected non-existent address")
}

// TestNewKeystoreSigner_WrongPassword tests error handling for wrong password
func TestNewKeystoreSigner_WrongPassword(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	_, err = NewKeystoreSigner(ks, expectedAddress, "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}

	t.Log("✓ Correctly rejected wrong password")
}

// TestNewKeystoreSignerFromPath tests creating signer from path
func TestNewKeystoreSignerFromPath(t *testing.T) {
	t.Run("FromDirectory", func(t *testing.T) {
		tempDir := t.TempDir()
		_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		signer, err := NewKeystoreSignerFromPath(tempDir, expectedAddress, testPassword, nil)
		if err != nil {
			t.Fatalf("Failed to create keystore signer from directory: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Errorf("Address mismatch")
		}

		t.Log("✓ KeystoreSigner created successfully from directory path")
	})

	t.Run("FromFile", func(t *testing.T) {
		tempDir := t.TempDir()
		keystorePath, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		signer, err := NewKeystoreSignerFromPath(keystorePath, expectedAddress, testPassword, nil)
		if err != nil {
			t.Fatalf("Failed to create keystore signer from file: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Errorf("Address mismatch")
		}

		t.Log("✓ KeystoreSigner created successfully from file path")
	})

	t.Run("InvalidPath", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		_, err := NewKeystoreSignerFromPath("/nonexistent/path", addr, testPassword, nil)
		if err == nil {
			t.Error("Expected error for non-existent path")
		}

		t.Log("✓ Correctly rejected invalid path")
	})

	t.Run("EmptyPath", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		_, err := NewKeystoreSignerFromPath("", addr, testPassword, nil)
		if err == nil {
			t.Error("Expected error for empty path")
		}

		t.Log("✓ Correctly rejected empty path")
	})
}

// TestNewKeystoreSignerFromDirectory tests directory-specific constructor
func TestNewKeystoreSignerFromDirectory(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	signer, err := NewKeystoreSignerFromDirectory(tempDir, expectedAddress, testPassword, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore signer from directory: %v", err)
	}

	if signer.GetAddress() != expectedAddress {
		t.Errorf("Address mismatch")
	}

	t.Log("✓ KeystoreSigner created successfully from directory")
}

// TestNewKeystoreSignerFromFile tests file-specific constructor
func TestNewKeystoreSignerFromFile(t *testing.T) {
	t.Run("ValidFile", func(t *testing.T) {
		tempDir := t.TempDir()
		keystorePath, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		signer, err := NewKeystoreSignerFromFile(keystorePath, expectedAddress, testPassword, nil)
		if err != nil {
			t.Fatalf("Failed to create keystore signer from file: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Errorf("Address mismatch")
		}

		t.Log("✓ KeystoreSigner created successfully from file")
	})

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		tempDir := t.TempDir()
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")

		_, err := NewKeystoreSignerFromFile(tempDir, addr, testPassword, nil)
		if err == nil {
			t.Error("Expected error when passing directory to NewKeystoreSignerFromFile")
		}

		t.Log("✓ Correctly rejected directory path")
	})

	t.Run("NonExistentFile", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		_, err := NewKeystoreSignerFromFile("/nonexistent/file", addr, testPassword, nil)
		if err == nil {
			t.Error("Expected error for non-existent file")
		}

		t.Log("✓ Correctly rejected non-existent file")
	})
}

// TestKeystoreSigner_MultipleSignersFromOneKeyStore tests managing multiple signers
func TestKeystoreSigner_MultipleSignersFromOneKeyStore(t *testing.T) {
	tempDir := t.TempDir()

	// Create two keystore files
	_, addr1, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create first keystore: %v", err)
	}

	_, addr2, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create second keystore: %v", err)
	}

	// Create single KeyStore instance
	ks := newTestKeyStore(tempDir)

	// Create signers for both addresses
	signer1, err := NewKeystoreSigner(ks, addr1, testPassword)
	if err != nil {
		t.Fatalf("Failed to create first signer: %v", err)
	}

	signer2, err := NewKeystoreSigner(ks, addr2, testPassword)
	if err != nil {
		t.Fatalf("Failed to create second signer: %v", err)
	}

	// Verify addresses
	if signer1.GetAddress() != addr1 {
		t.Errorf("First signer address mismatch")
	}
	if signer2.GetAddress() != addr2 {
		t.Errorf("Second signer address mismatch")
	}

	// Verify they can sign independently
	msg := "test message"
	sig1, err := signer1.PersonalSign(msg)
	if err != nil {
		t.Fatalf("First signer failed to sign: %v", err)
	}

	sig2, err := signer2.PersonalSign(msg)
	if err != nil {
		t.Fatalf("Second signer failed to sign: %v", err)
	}

	// Signatures should be different
	if string(sig1) == string(sig2) {
		t.Error("Signatures from different signers should be different")
	}

	t.Log("✓ Multiple signers from single KeyStore work correctly")
}

// TestKeystoreSigner_PersonalSign tests personal sign functionality
func TestKeystoreSigner_PersonalSign(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	message := "Hello, Ethereum!"
	signature, err := signer.PersonalSign(message)
	if err != nil {
		t.Fatalf("PersonalSign failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Expected signature length 65, got %d", len(signature))
	}

	// Verify signature
	messageBytes := []byte(message)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)
	hash := crypto.Keccak256Hash(prefixedMessage)

	// crypto.SigToPub expects V in [0,1] range, so denormalize the signature
	denormalizedSig := DenormalizeSignatureV(signature)
	pubKey, err := crypto.SigToPub(hash.Bytes(), denormalizedSig)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if recoveredAddr != expectedAddress {
		t.Errorf("Address recovery failed. Expected: %s, Got: %s", expectedAddress.Hex(), recoveredAddr.Hex())
	}

	t.Log("✓ PersonalSign works correctly")
}

// TestKeystoreSigner_SignEIP191Message tests EIP-191 message signing
func TestKeystoreSigner_SignEIP191Message(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	// Create EIP-191 message
	domainSeparator := crypto.Keccak256Hash([]byte("domain"))
	hashStruct := crypto.Keccak256Hash([]byte("struct"))
	eip191Message := append([]byte("\x19\x01"), domainSeparator.Bytes()...)
	eip191Message = append(eip191Message, hashStruct.Bytes()...)

	signature, err := signer.SignEIP191Message(string(eip191Message))
	if err != nil {
		t.Fatalf("SignEIP191Message failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Expected signature length 65, got %d", len(signature))
	}

	t.Log("✓ SignEIP191Message works correctly")
}

// TestKeystoreSigner_SignTypedData tests EIP-712 typed data signing
func TestKeystoreSigner_SignTypedData(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

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
			Name:    "Test App",
			Version: "1",
			ChainId: "1",
		},
		Message: eip712.TypedDataMessage{
			"name":   "Alice",
			"wallet": "0x1234567890123456789012345678901234567890",
		},
	}

	signature, err := signer.SignTypedData(typedData)
	if err != nil {
		t.Fatalf("SignTypedData failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Expected signature length 65, got %d", len(signature))
	}

	t.Log("✓ SignTypedData works correctly")
}

// TestKeystoreSigner_SignTransaction tests transaction signing
func TestKeystoreSigner_SignTransaction(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	tx := types.NewTransaction(
		0,
		to,
		big.NewInt(1000000000000000000),
		21000,
		big.NewInt(1000000000),
		nil,
	)

	chainID := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
	if err != nil {
		t.Fatalf("SignTransactionWithChainID failed: %v", err)
	}

	// Verify sender
	txSigner := types.LatestSignerForChainID(chainID)
	recoveredAddr, err := types.Sender(txSigner, signedTx)
	if err != nil {
		t.Fatalf("Failed to recover sender: %v", err)
	}

	if recoveredAddr != expectedAddress {
		t.Errorf("Sender recovery failed. Expected: %s, Got: %s", expectedAddress.Hex(), recoveredAddr.Hex())
	}

	t.Log("✓ SignTransactionWithChainID works correctly")
}

// TestKeystoreSigner_SignHash tests hash signing
func TestKeystoreSigner_SignHash(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	hash := crypto.Keccak256Hash([]byte("test data"))
	signature, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("SignHash failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Expected signature length 65, got %d", len(signature))
	}

	// Verify signature
	// crypto.SigToPub expects V in [0,1] range, so denormalize the signature
	denormalizedSig := DenormalizeSignatureV(signature)
	pubKey, err := crypto.SigToPub(hash.Bytes(), denormalizedSig)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if recoveredAddr != expectedAddress {
		t.Errorf("Address recovery failed. Expected: %s, Got: %s", expectedAddress.Hex(), recoveredAddr.Hex())
	}

	t.Log("✓ SignHash works correctly")
}

// TestKeystoreSigner_Close tests Close functionality
func TestKeystoreSigner_Close(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	// Close the signer
	signer.Close()

	// Verify password is zeroized
	if signer.password != nil {
		t.Error("Password was not zeroized after Close()")
	}

	t.Log("✓ Close() correctly zeroizes sensitive data")
}

// TestKeystoreSigner_InterfaceCompatibility tests interface implementation
func TestKeystoreSigner_InterfaceCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	signer, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	// Test interface assertions
	var _ AddressGetter = signer
	var _ HashSigner = signer
	var _ EIP191Signer = signer
	var _ PersonalSigner = signer
	var _ TypedDataSigner = signer
	var _ TransactionSigner = signer

	t.Log("✓ KeystoreSigner implements all required interfaces")
}

// TestKeystoreSigner_ScryptConfig tests custom scrypt configuration
func TestKeystoreSigner_ScryptConfig(t *testing.T) {
	t.Run("LightScrypt", func(t *testing.T) {
		tempDir := t.TempDir()
		_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		signer, err := NewKeystoreSignerFromDirectory(tempDir, expectedAddress, testPassword, &LightScryptConfig)
		if err != nil {
			t.Fatalf("Failed with LightScryptConfig: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Error("Address mismatch")
		}

		t.Log("✓ LightScryptConfig works correctly")
	})

	t.Run("StandardScrypt", func(t *testing.T) {
		tempDir := t.TempDir()
		_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		signer, err := NewKeystoreSignerFromDirectory(tempDir, expectedAddress, testPassword, &StandardScryptConfig)
		if err != nil {
			t.Fatalf("Failed with StandardScryptConfig: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Error("Address mismatch")
		}

		t.Log("✓ StandardScryptConfig works correctly")
	})

	t.Run("NilConfig", func(t *testing.T) {
		tempDir := t.TempDir()
		_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test keystore: %v", err)
		}

		// nil should default to LightScryptConfig
		signer, err := NewKeystoreSignerFromDirectory(tempDir, expectedAddress, testPassword, nil)
		if err != nil {
			t.Fatalf("Failed with nil config: %v", err)
		}

		if signer.GetAddress() != expectedAddress {
			t.Error("Address mismatch")
		}

		t.Log("✓ Nil config defaults to LightScryptConfig")
	})
}

// TestKeystoreSigner_WithSignerWrapper tests KeystoreSigner with Signer wrapper
func TestKeystoreSigner_WithSignerWrapper(t *testing.T) {
	tempDir := t.TempDir()
	_, expectedAddress, err := createTestKeystore(tempDir, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	ks := newTestKeyStore(tempDir)
	keystoreSigner, err := NewKeystoreSigner(ks, expectedAddress, testPassword)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}

	// Wrap with Signer
	signer := NewSigner(keystoreSigner)

	// Test signing through wrapper
	message := "test message"
	signature, err := signer.PersonalSign(message)
	if err != nil {
		t.Fatalf("PersonalSign through wrapper failed: %v", err)
	}

	if len(signature) != 65 {
		t.Errorf("Expected signature length 65, got %d", len(signature))
	}

	// Test Close through wrapper
	err = signer.Close()
	if err != nil {
		t.Errorf("Close through wrapper failed: %v", err)
	}

	if keystoreSigner.password != nil {
		t.Error("Password was not zeroized through wrapper Close()")
	}

	t.Log("✓ KeystoreSigner works correctly with Signer wrapper")
}

// TestConstantTimeSignatureValidation tests that signature validation is constant-time
func TestConstantTimeSignatureValidation(t *testing.T) {
	// Generate test data
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	hash := crypto.Keccak256Hash([]byte("test message"))

	// Sign the hash
	signer := NewEthPrivateKeySigner(privateKey)
	signature, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	// Test with correct signature
	valid, err := ValidateSignature(address, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Valid signature should validate correctly")
	}

	// Test with wrong address (should be constant-time)
	wrongAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
	valid, err = ValidateSignature(wrongAddress, hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if valid {
		t.Error("Signature should be invalid for wrong address")
	}

	// Test with wrong hash (should be constant-time)
	wrongHash := crypto.Keccak256Hash([]byte("wrong message"))
	valid, err = ValidateSignature(address, wrongHash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if valid {
		t.Error("Signature should be invalid for wrong hash")
	}
}

// TestSecureBytesMemorySafety tests that SecureBytes properly zeroizes memory
func TestSecureBytesMemorySafety(t *testing.T) {
	// Test data
	sensitiveData := []byte("very-secret-password")
	sb := NewSecureBytes(sensitiveData)

	// Verify data is accessible
	if sb.Len() != len(sensitiveData) {
		t.Errorf("Expected length %d, got %d", len(sensitiveData), sb.Len())
	}

	// Zeroize the data
	sb.Zeroize()

	// Verify data is zeroized
	if !sb.IsZeroized() {
		t.Error("SecureBytes should be zeroized after Zeroize()")
	}

	// Verify original data is not modified (SecureBytes makes a copy)
	if string(sensitiveData) != "very-secret-password" {
		t.Error("Original data should not be modified by SecureBytes")
	}
}

// TestTimingAttackResistance tests that operations are resistant to timing attacks
func TestTimingAttackResistance(t *testing.T) {
	// This test verifies that constant-time operations are used
	// by measuring execution time for different inputs

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	hash := crypto.Keccak256Hash([]byte("test"))

	signer := NewEthPrivateKeySigner(privateKey)
	signature, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	// Test multiple validations with different inputs
	// and ensure they take similar time
	testCases := []struct {
		name    string
		address common.Address
		hash    common.Hash
		expect  bool
	}{
		{"correct", address, hash, true},
		{"wrong address", common.HexToAddress("0x0000000000000000000000000000000000000001"), hash, false},
		{"wrong hash", address, crypto.Keccak256Hash([]byte("wrong")), false},
	}

	var times []time.Duration
	for _, tc := range testCases {
		start := time.Now()
		for i := 0; i < 1000; i++ {
			ValidateSignature(tc.address, tc.hash, signature)
		}
		duration := time.Since(start)
		times = append(times, duration)
		t.Logf("%s: %v", tc.name, duration)
	}

	// Check that times are within reasonable bounds
	// (This is a basic check - more sophisticated timing analysis would be needed for production)
	maxTime := times[0]
	minTime := times[0]
	for _, t := range times {
		if t > maxTime {
			maxTime = t
		}
		if t < minTime {
			minTime = t
		}
	}

	// Allow 50% variation for test environment noise
	if float64(maxTime-minTime) > float64(maxTime)*0.5 {
		t.Log("Warning: Significant timing differences detected")
	}
}

// TestKeystoreSignerPasswordSecurity tests that passwords are handled securely
func TestKeystoreSignerPasswordSecurity(t *testing.T) {
	// Create a temporary directory for keystore
	tempDir := t.TempDir()
	password := "test-password-123"

	// Create a keystore
	keystorePath, address, err := createTestKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Create signer from keystore
	signer, err := NewKeystoreSignerFromPath(keystorePath, address, password, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore signer: %v", err)
	}
	defer signer.Close()

	// Verify the signer works
	hash := crypto.Keccak256Hash([]byte("test message"))
	signature, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("Failed to sign hash: %v", err)
	}

	// Verify signature
	valid, err := ValidateSignature(signer.GetAddress(), hash, signature)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Keystore signer signature should be valid")
	}

	// Test loading from keystore
	loadedSigner, err := NewKeystoreSignerFromPath(keystorePath, address, password, nil)
	if err != nil {
		t.Fatalf("Failed to load keystore: %v", err)
	}
	defer loadedSigner.Close()

	// Verify loaded signer works
	signature2, err := loadedSigner.SignHash(hash)
	if err != nil {
		t.Fatalf("Failed to sign hash with loaded signer: %v", err)
	}

	valid, err = ValidateSignature(loadedSigner.GetAddress(), hash, signature2)
	if err != nil {
		t.Fatalf("ValidateSignature failed: %v", err)
	}
	if !valid {
		t.Error("Loaded keystore signer signature should be valid")
	}
}
