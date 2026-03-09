package keystore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	ethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	enhancedKeystoreVersion = 1
)

// KeyType represents the type of cryptographic key.
type KeyType string

const (
	KeyTypeEd25519   KeyType = "ed25519"
	KeyTypeSecp256k1 KeyType = "secp256k1"
)

// KeyFormat represents the input/output format for private keys.
type KeyFormat string

const (
	KeyFormatHex    KeyFormat = "hex"
	KeyFormatBase64 KeyFormat = "base64"
	KeyFormatPEM    KeyFormat = "pem"
)

// secp256k1N is the order of the secp256k1 curve.
var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// EnhancedKeyFile represents the encrypted enhanced key file on disk.
type EnhancedKeyFile struct {
	Version    int                    `json:"version"`
	KeyType    KeyType                `json:"key_type"`
	Identifier string                 `json:"identifier"`
	Crypto     ethkeystore.CryptoJSON `json:"crypto"`
	Label      string                 `json:"label,omitempty"`
}

// EnhancedKeyInfo contains metadata readable without decryption.
type EnhancedKeyInfo struct {
	KeyType    KeyType
	Identifier string
	Label      string
	Path       string
}

// ValidateKeyBytes checks if the raw key bytes are valid for the given key type.
// It also validates compatibility with secp256k1 curve order since we use
// go-ethereum's EncryptDataV3 which stores arbitrary bytes, but we proactively
// check so that the key could also be loaded via the native ECDSA path if needed.
func ValidateKeyBytes(keyBytes []byte, keyType KeyType) error {
	switch keyType {
	case KeyTypeEd25519:
		if len(keyBytes) != ed25519.SeedSize {
			return fmt.Errorf("ed25519 key must be %d bytes, got %d", ed25519.SeedSize, len(keyBytes))
		}
	case KeyTypeSecp256k1:
		if len(keyBytes) != 32 {
			return fmt.Errorf("secp256k1 key must be 32 bytes, got %d", len(keyBytes))
		}
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	keyInt := new(big.Int).SetBytes(keyBytes)
	if keyInt.Sign() == 0 {
		return fmt.Errorf("key bytes cannot be all zeros")
	}
	if keyInt.Cmp(secp256k1N) >= 0 {
		return fmt.Errorf("key bytes exceed secp256k1 curve order; please regenerate the key")
	}

	return nil
}

// ParseKeyInput parses raw key bytes from the given format.
func ParseKeyInput(input []byte, format KeyFormat, keyType KeyType) ([]byte, error) {
	switch format {
	case KeyFormatHex:
		hexStr := strings.TrimPrefix(strings.TrimSpace(string(input)), "0x")
		keyBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex input: %w", err)
		}
		return keyBytes, nil

	case KeyFormatBase64:
		trimmed := strings.TrimSpace(string(input))
		keyBytes, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			keyBytes, err = base64.RawStdEncoding.DecodeString(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 input: %w", err)
			}
		}
		return keyBytes, nil

	case KeyFormatPEM:
		block, _ := pem.Decode(input)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}

		// Try PKCS8 first
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			switch k := privKey.(type) {
			case ed25519.PrivateKey:
				return k.Seed(), nil
			default:
				return nil, fmt.Errorf("unsupported PKCS8 key type: %T", privKey)
			}
		}

		// Fall back to raw bytes from PEM block
		return block.Bytes, nil

	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// FormatKeyOutput formats raw key bytes into the given format.
func FormatKeyOutput(keyBytes []byte, format KeyFormat, keyType KeyType) ([]byte, error) {
	switch format {
	case KeyFormatHex:
		return []byte(hex.EncodeToString(keyBytes)), nil

	case KeyFormatBase64:
		return []byte(base64.StdEncoding.EncodeToString(keyBytes)), nil

	case KeyFormatPEM:
		var pemType string
		var derBytes []byte

		switch keyType {
		case KeyTypeEd25519:
			privKey := ed25519.NewKeyFromSeed(keyBytes)
			der, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ed25519 key to PKCS8: %w", err)
			}
			pemType = "PRIVATE KEY"
			derBytes = der
		default:
			// For non-ed25519, wrap raw bytes in a generic PEM block
			pemType = "PRIVATE KEY"
			derBytes = keyBytes
		}

		block := &pem.Block{
			Type:  pemType,
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(block), nil

	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// deriveIdentifier derives a human-readable identifier from key bytes and type.
func deriveIdentifier(keyBytes []byte, keyType KeyType) string {
	switch keyType {
	case KeyTypeEd25519:
		privKey := ed25519.NewKeyFromSeed(keyBytes)
		pubKey := privKey.Public().(ed25519.PublicKey)
		return hex.EncodeToString(pubKey)
	default:
		hash := sha256.Sum256(keyBytes)
		return hex.EncodeToString(hash[:20])
	}
}

// enhancedKeyFileName returns the filename for an enhanced key file.
func enhancedKeyFileName(keyType KeyType, identifier string) string {
	return string(keyType) + "--" + identifier + ".json"
}

// CreateEnhancedKey creates a new enhanced key of the given type.
func CreateEnhancedKey(dir string, keyType KeyType, password []byte, label string) (identifier, path string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}

	var keyBytes []byte
	switch keyType {
	case KeyTypeEd25519:
		for {
			_, privKey, genErr := ed25519.GenerateKey(nil)
			if genErr != nil {
				return "", "", fmt.Errorf("failed to generate ed25519 key: %w", genErr)
			}
			keyBytes = make([]byte, ed25519.SeedSize)
			copy(keyBytes, privKey.Seed())
			if ValidateKeyBytes(keyBytes, keyType) == nil {
				break
			}
			SecureZeroize(keyBytes)
		}
	default:
		return "", "", fmt.Errorf("unsupported key type for creation: %s (use native keystore for secp256k1)", keyType)
	}
	defer SecureZeroize(keyBytes)

	return writeEnhancedKeyFile(dir, keyBytes, keyType, password, label)
}

// ImportEnhancedKey imports a key from the given input and format.
func ImportEnhancedKey(dir string, input []byte, keyType KeyType, format KeyFormat, password []byte, label string) (identifier, path string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(input) == 0 {
		return "", "", fmt.Errorf("key input cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}

	keyBytes, err := ParseKeyInput(input, format, keyType)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse key input: %w", err)
	}
	defer SecureZeroize(keyBytes)

	if err := ValidateKeyBytes(keyBytes, keyType); err != nil {
		return "", "", fmt.Errorf("key validation failed: %w", err)
	}

	return writeEnhancedKeyFile(dir, keyBytes, keyType, password, label)
}

// ExportEnhancedKey decrypts and exports a key in the given format.
func ExportEnhancedKey(keystorePath string, password []byte, format KeyFormat) ([]byte, error) {
	if keystorePath == "" {
		return nil, fmt.Errorf("keystore path cannot be empty")
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}

	kf, err := readEnhancedKeyFile(keystorePath)
	if err != nil {
		return nil, err
	}

	keyBytes, err := ethkeystore.DecryptDataV3(kf.Crypto, string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}
	defer SecureZeroize(keyBytes)

	output, err := FormatKeyOutput(keyBytes, format, kf.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to format key output: %w", err)
	}

	return output, nil
}

// ExportNativeKey decrypts a native go-ethereum keystore and returns the raw private key bytes.
func ExportNativeKey(keystorePath string, password []byte) ([]byte, error) {
	if keystorePath == "" {
		return nil, fmt.Errorf("keystore path cannot be empty")
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}

	keyjson, err := os.ReadFile(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore: %w", err)
	}

	key, err := ethkeystore.DecryptKey(keyjson, string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keystore: %w", err)
	}
	defer zeroPrivateKey(key.PrivateKey)

	rawBytes := crypto.FromECDSA(key.PrivateKey)
	return rawBytes, nil
}

// GetEnhancedKeyInfo reads enhanced key metadata without decryption.
func GetEnhancedKeyInfo(keystorePath string) (*EnhancedKeyInfo, error) {
	if keystorePath == "" {
		return nil, fmt.Errorf("keystore path cannot be empty")
	}

	kf, err := readEnhancedKeyFile(keystorePath)
	if err != nil {
		return nil, err
	}

	return &EnhancedKeyInfo{
		KeyType:    kf.KeyType,
		Identifier: kf.Identifier,
		Label:      kf.Label,
		Path:       keystorePath,
	}, nil
}

// VerifyEnhancedKeyPassword verifies password can decrypt the enhanced key.
func VerifyEnhancedKeyPassword(keystorePath string, password []byte) error {
	if keystorePath == "" {
		return fmt.Errorf("keystore path cannot be empty")
	}
	if len(password) == 0 {
		return ErrEmptyPassword
	}

	kf, err := readEnhancedKeyFile(keystorePath)
	if err != nil {
		return err
	}

	keyBytes, err := ethkeystore.DecryptDataV3(kf.Crypto, string(password))
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}
	SecureZeroize(keyBytes)
	return nil
}

// ChangeEnhancedKeyPassword changes the password of an enhanced key file.
func ChangeEnhancedKeyPassword(keystorePath string, currentPassword, newPassword []byte) error {
	if keystorePath == "" {
		return fmt.Errorf("keystore path cannot be empty")
	}
	if len(currentPassword) == 0 {
		return fmt.Errorf("current password cannot be empty")
	}
	if len(newPassword) == 0 {
		return fmt.Errorf("new password cannot be empty")
	}

	kf, err := readEnhancedKeyFile(keystorePath)
	if err != nil {
		return err
	}

	keyBytes, err := ethkeystore.DecryptDataV3(kf.Crypto, string(currentPassword))
	if err != nil {
		return fmt.Errorf("failed to decrypt key (wrong password?): %w", err)
	}
	defer SecureZeroize(keyBytes)

	newCrypto, err := ethkeystore.EncryptDataV3(keyBytes, newPassword, defaultScryptN, defaultScryptP)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new password: %w", err)
	}

	kf.Crypto = newCrypto

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key file: %w", err)
	}

	if err := os.WriteFile(keystorePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// ListEnhancedKeys lists all enhanced key files in a directory.
func ListEnhancedKeys(dir string) ([]EnhancedKeyInfo, error) {
	if dir == "" {
		return nil, fmt.Errorf("directory cannot be empty")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var keys []EnhancedKeyInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "UTC--") || strings.HasPrefix(name, hdwalletFilePrefix) {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if !strings.Contains(name, "--") {
			continue
		}

		path := filepath.Join(dir, name)
		info, err := GetEnhancedKeyInfo(path)
		if err != nil {
			continue
		}
		keys = append(keys, *info)
	}

	return keys, nil
}

// IsEnhancedKeyFile checks if the given file is an enhanced key file by reading its JSON.
func IsEnhancedKeyFile(filePath string) bool {
	_, err := readEnhancedKeyFile(filePath)
	return err == nil
}

// --- internal helpers ---

func writeEnhancedKeyFile(dir string, keyBytes []byte, keyType KeyType, password []byte, label string) (string, string, error) {
	identifier := deriveIdentifier(keyBytes, keyType)
	fileName := enhancedKeyFileName(keyType, identifier)
	filePath := filepath.Join(dir, fileName)

	cryptoJSON, err := ethkeystore.EncryptDataV3(keyBytes, password, defaultScryptN, defaultScryptP)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	kf := EnhancedKeyFile{
		Version:    enhancedKeystoreVersion,
		KeyType:    keyType,
		Identifier: identifier,
		Crypto:     cryptoJSON,
		Label:      label,
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal key file: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return "", "", fmt.Errorf("enhanced key file already exists: %s", filePath)
		}
		return "", "", fmt.Errorf("failed to create key file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(filePath)
		return "", "", fmt.Errorf("failed to write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close key file: %w", err)
	}

	return identifier, filePath, nil
}

func readEnhancedKeyFile(filePath string) (*EnhancedKeyFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("enhanced key file not found: %s", filePath)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var kf EnhancedKeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	if kf.Version == 0 || kf.KeyType == "" || kf.Identifier == "" {
		return nil, fmt.Errorf("invalid enhanced key file: missing required fields")
	}

	return &kf, nil
}
