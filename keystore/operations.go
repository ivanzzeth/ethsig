package keystore

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// KeystoreInfo contains information about a keystore file.
type KeystoreInfo struct {
	Address string `json:"address"`
	Path    string `json:"path"`
}

// CreateKeystore creates a new keystore with a randomly generated key.
//
// Parameters:
//   - dir: Directory to store the keystore file (will be created if not exists)
//   - password: Password to encrypt the keystore
//
// Returns:
//   - address: The Ethereum address of the new key (0x prefixed)
//   - path: Full path to the created keystore file
//   - error: Any error that occurred
func CreateKeystore(dir string, password []byte) (string, string, error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	ks := keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.NewAccount(string(password))
	if err != nil {
		return "", "", fmt.Errorf("failed to create account: %w", err)
	}

	return account.Address.Hex(), account.URL.Path, nil
}

// ImportPrivateKey imports a hex-encoded private key into a new keystore.
//
// Parameters:
//   - dir: Directory to store the keystore file (will be created if not exists)
//   - privateKeyHex: Hex-encoded private key (with or without 0x prefix)
//   - password: Password to encrypt the keystore
//
// Returns:
//   - address: The Ethereum address derived from the private key (0x prefixed)
//   - path: Full path to the created keystore file
//   - error: Any error that occurred
func ImportPrivateKey(dir string, privateKeyHex []byte, password []byte) (string, string, error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}
	if len(privateKeyHex) == 0 {
		return "", "", fmt.Errorf("private key cannot be empty")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Clean up hex string
	keyHex := strings.TrimPrefix(string(privateKeyHex), "0x")
	keyHex = strings.TrimSpace(keyHex)

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", "", fmt.Errorf("invalid hex private key: %w", err)
	}
	defer SecureZeroize(keyBytes)

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid private key: %w", err)
	}

	ks := keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.ImportECDSA(privateKey, string(password))
	if err != nil {
		return "", "", fmt.Errorf("failed to import key: %w", err)
	}

	// Zero out the private key in memory
	zeroPrivateKey(privateKey)

	return account.Address.Hex(), account.URL.Path, nil
}

// ChangePassword changes the password of an existing keystore file.
//
// Parameters:
//   - keystorePath: Path to the keystore file
//   - currentPassword: Current password
//   - newPassword: New password
//
// Returns:
//   - error: Any error that occurred
func ChangePassword(keystorePath string, currentPassword, newPassword []byte) error {
	if keystorePath == "" {
		return fmt.Errorf("keystore path cannot be empty")
	}
	if len(currentPassword) == 0 {
		return fmt.Errorf("current password cannot be empty")
	}
	if len(newPassword) == 0 {
		return fmt.Errorf("new password cannot be empty")
	}

	// Read keystore JSON
	keyjson, err := os.ReadFile(keystorePath)
	if err != nil {
		return fmt.Errorf("failed to read keystore: %w", err)
	}

	// Decrypt with current password
	key, err := keystore.DecryptKey(keyjson, string(currentPassword))
	if err != nil {
		return fmt.Errorf("failed to decrypt keystore (wrong password?): %w", err)
	}
	defer zeroPrivateKey(key.PrivateKey)

	// Re-encrypt with new password
	newKeyjson, err := keystore.EncryptKey(key, string(newPassword), keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new password: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(keystorePath, newKeyjson, 0600); err != nil {
		return fmt.Errorf("failed to write keystore: %w", err)
	}

	return nil
}

// ListKeystores lists all keystore files in a directory.
//
// Parameters:
//   - dir: Directory to scan for keystore files
//
// Returns:
//   - []KeystoreInfo: List of keystores found
//   - error: Any error that occurred
func ListKeystores(dir string) ([]KeystoreInfo, error) {
	if dir == "" {
		return nil, fmt.Errorf("directory cannot be empty")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var keystores []KeystoreInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		keyjson, err := os.ReadFile(path)
		if err != nil {
			continue // Skip unreadable files
		}

		// Try to parse as keystore
		var keystoreFile struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(keyjson, &keystoreFile); err != nil || keystoreFile.Address == "" {
			continue // Skip non-keystore files
		}

		// Normalize address format
		address := keystoreFile.Address
		if !strings.HasPrefix(address, "0x") {
			address = "0x" + address
		}
		address = common.HexToAddress(address).Hex() // Checksum

		keystores = append(keystores, KeystoreInfo{
			Address: address,
			Path:    path,
		})
	}

	return keystores, nil
}

// GetKeystoreAddress reads a keystore file and returns the address without decrypting.
//
// Parameters:
//   - keystorePath: Path to the keystore file
//
// Returns:
//   - address: The Ethereum address (0x prefixed, checksummed)
//   - error: Any error that occurred
func GetKeystoreAddress(keystorePath string) (string, error) {
	if keystorePath == "" {
		return "", fmt.Errorf("keystore path cannot be empty")
	}

	keyjson, err := os.ReadFile(keystorePath)
	if err != nil {
		return "", fmt.Errorf("failed to read keystore: %w", err)
	}

	var keystoreFile struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(keyjson, &keystoreFile); err != nil {
		return "", fmt.Errorf("failed to parse keystore: %w", err)
	}

	if keystoreFile.Address == "" {
		return "", fmt.Errorf("keystore does not contain address")
	}

	// Normalize address format
	address := keystoreFile.Address
	if !strings.HasPrefix(address, "0x") {
		address = "0x" + address
	}

	return common.HexToAddress(address).Hex(), nil
}

// VerifyPassword verifies that the password can decrypt the keystore.
//
// Parameters:
//   - keystorePath: Path to the keystore file
//   - password: Password to verify
//
// Returns:
//   - error: nil if password is correct, error otherwise
func VerifyPassword(keystorePath string, password []byte) error {
	if keystorePath == "" {
		return fmt.Errorf("keystore path cannot be empty")
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	keyjson, err := os.ReadFile(keystorePath)
	if err != nil {
		return fmt.Errorf("failed to read keystore: %w", err)
	}

	key, err := keystore.DecryptKey(keyjson, string(password))
	if err != nil {
		return fmt.Errorf("failed to decrypt keystore: %w", err)
	}

	// Zero out the private key immediately
	zeroPrivateKey(key.PrivateKey)

	return nil
}

// zeroPrivateKey zeros out a private key in memory
func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key == nil {
		return
	}
	if key.D != nil {
		key.D.SetInt64(0)
	}
}
