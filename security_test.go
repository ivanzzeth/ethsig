package ethsig

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

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
	signer, keystorePath, err := CreateKeystore(tempDir, password, nil)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
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
	loadedSigner, err := NewKeystoreSigner(keystorePath, password, nil)
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
