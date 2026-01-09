package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCreateKeystore(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	address, path, err := CreateKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	// Verify address format
	if !common.IsHexAddress(address) {
		t.Errorf("Invalid address format: %s", address)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Keystore file was not created: %s", path)
	}

	// Verify we can read the address back
	readAddress, err := GetKeystoreAddress(path)
	if err != nil {
		t.Fatalf("GetKeystoreAddress failed: %v", err)
	}
	if readAddress != address {
		t.Errorf("Address mismatch: got %s, want %s", readAddress, address)
	}

	// Verify password works
	if err := VerifyPassword(path, password); err != nil {
		t.Errorf("VerifyPassword failed: %v", err)
	}

	// Verify wrong password fails
	if err := VerifyPassword(path, []byte("wrong-password")); err == nil {
		t.Error("VerifyPassword should fail with wrong password")
	}
}

func TestCreateKeystore_EmptyDir(t *testing.T) {
	password := []byte("test-password")
	_, _, err := CreateKeystore("", password)
	if err == nil {
		t.Error("CreateKeystore should fail with empty directory")
	}
}

func TestCreateKeystore_EmptyPassword(t *testing.T) {
	tempDir := t.TempDir()
	_, _, err := CreateKeystore(tempDir, []byte{})
	if err == nil {
		t.Error("CreateKeystore should fail with empty password")
	}
}

func TestImportPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	// Known test private key (DO NOT use in production)
	// This key generates address: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
	privateKeyHex := []byte("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	expectedAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	address, path, err := ImportPrivateKey(tempDir, privateKeyHex, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}

	// Verify address matches expected
	if address != expectedAddress {
		t.Errorf("Address mismatch: got %s, want %s", address, expectedAddress)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Keystore file was not created: %s", path)
	}

	// Verify password works
	if err := VerifyPassword(path, password); err != nil {
		t.Errorf("VerifyPassword failed: %v", err)
	}
}

func TestImportPrivateKey_With0xPrefix(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	// With 0x prefix
	privateKeyHex := []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	expectedAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	address, _, err := ImportPrivateKey(tempDir, privateKeyHex, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}

	if address != expectedAddress {
		t.Errorf("Address mismatch: got %s, want %s", address, expectedAddress)
	}
}

func TestImportPrivateKey_InvalidHex(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password")
	_, _, err := ImportPrivateKey(tempDir, []byte("not-valid-hex"), password)
	if err == nil {
		t.Error("ImportPrivateKey should fail with invalid hex")
	}
}

func TestChangePassword(t *testing.T) {
	tempDir := t.TempDir()
	oldPassword := []byte("old-password-123")
	newPassword := []byte("new-password-456")

	// Create a keystore first
	_, path, err := CreateKeystore(tempDir, oldPassword)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	// Change password
	if err := ChangePassword(path, oldPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// Verify old password no longer works
	if err := VerifyPassword(path, oldPassword); err == nil {
		t.Error("Old password should no longer work")
	}

	// Verify new password works
	if err := VerifyPassword(path, newPassword); err != nil {
		t.Errorf("New password should work: %v", err)
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("correct-password")

	_, path, err := CreateKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	err = ChangePassword(path, []byte("wrong-password"), []byte("new-password"))
	if err == nil {
		t.Error("ChangePassword should fail with wrong current password")
	}
}

func TestListKeystores(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	// Create multiple keystores
	address1, _, err := CreateKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("CreateKeystore 1 failed: %v", err)
	}

	address2, _, err := CreateKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("CreateKeystore 2 failed: %v", err)
	}

	// Create a non-keystore file
	nonKeystorePath := filepath.Join(tempDir, "not-a-keystore.txt")
	if err := os.WriteFile(nonKeystorePath, []byte("hello"), 0600); err != nil {
		t.Fatalf("Failed to create non-keystore file: %v", err)
	}

	// List keystores
	keystores, err := ListKeystores(tempDir)
	if err != nil {
		t.Fatalf("ListKeystores failed: %v", err)
	}

	if len(keystores) != 2 {
		t.Errorf("Expected 2 keystores, got %d", len(keystores))
	}

	// Verify addresses are in the list
	addresses := make(map[string]bool)
	for _, ks := range keystores {
		addresses[ks.Address] = true
	}

	if !addresses[address1] {
		t.Errorf("Address 1 not found in list: %s", address1)
	}
	if !addresses[address2] {
		t.Errorf("Address 2 not found in list: %s", address2)
	}
}

func TestListKeystores_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	keystores, err := ListKeystores(tempDir)
	if err != nil {
		t.Fatalf("ListKeystores failed: %v", err)
	}

	if len(keystores) != 0 {
		t.Errorf("Expected 0 keystores, got %d", len(keystores))
	}
}

func TestListKeystores_NonExistentDir(t *testing.T) {
	_, err := ListKeystores("/nonexistent/directory")
	if err == nil {
		t.Error("ListKeystores should fail with non-existent directory")
	}
}

func TestGetKeystoreAddress(t *testing.T) {
	tempDir := t.TempDir()
	password := []byte("test-password-123")

	expectedAddress, path, err := CreateKeystore(tempDir, password)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	address, err := GetKeystoreAddress(path)
	if err != nil {
		t.Fatalf("GetKeystoreAddress failed: %v", err)
	}

	if address != expectedAddress {
		t.Errorf("Address mismatch: got %s, want %s", address, expectedAddress)
	}
}

func TestGetKeystoreAddress_InvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	invalidPath := filepath.Join(tempDir, "invalid.json")

	// Write invalid JSON
	if err := os.WriteFile(invalidPath, []byte("not json"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	_, err := GetKeystoreAddress(invalidPath)
	if err == nil {
		t.Error("GetKeystoreAddress should fail with invalid JSON")
	}
}

func TestSecureZeroize(t *testing.T) {
	data := []byte("sensitive-data-123")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZeroize(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}

	// Verify nil doesn't panic
	SecureZeroize(nil)
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal", []byte("hello"), []byte("hello"), true},
		{"not equal", []byte("hello"), []byte("world"), false},
		{"different length", []byte("hello"), []byte("hi"), false},
		{"empty equal", []byte{}, []byte{}, true},
		{"one empty", []byte("hello"), []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("bytesEqual(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}
