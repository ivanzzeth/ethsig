package ethsig

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

var (
	// Verify KeystoreSigner implements all required interfaces
	_ AddressGetter     = (*KeystoreSigner)(nil)
	_ HashSigner        = (*KeystoreSigner)(nil)
	_ EIP191Signer      = (*KeystoreSigner)(nil)
	_ PersonalSigner    = (*KeystoreSigner)(nil)
	_ TypedDataSigner   = (*KeystoreSigner)(nil)
	_ TransactionSigner = (*KeystoreSigner)(nil)
)

// KeystoreSigner implements Signer using an Ethereum keystore file
// It loads the private key from a keystore file and delegates all signing operations
// to the keystore's signing methods
type KeystoreSigner struct {
	privateKeySigner *EthPrivateKeySigner
	keystorePath     string
	address          common.Address
	keyStore         *keystore.KeyStore
	account          accounts.Account
	password         *SecureBytes
}

// NewKeystoreSigner creates a new KeystoreSigner instance by loading a private key from a keystore file
// Parameters:
//   - keystorePath: Path to the keystore file
//   - password: Password to decrypt the keystore file
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred during loading or decryption
func NewKeystoreSigner(keystorePath, password string) (*KeystoreSigner, error) {
	if keystorePath == "" {
		return nil, fmt.Errorf("keystore path cannot be empty")
	}

	// Get the directory containing the keystore file
	keystoreDir := filepath.Dir(keystorePath)
	
	// Create a keystore manager in the same directory as the keystore file
	ks := keystore.NewKeyStore(keystoreDir, keystore.StandardScryptN, keystore.StandardScryptP)

	// Find the account in the keystore
	accountList := ks.Accounts()
	var account accounts.Account
	found := false
	
	for _, acc := range accountList {
		if acc.URL.Path == keystorePath {
			account = acc
			found = true
			break
		}
	}
	
	if !found {
		return nil, fmt.Errorf("keystore file not found in directory: %s", keystorePath)
	}

	// Get the address from the account
	address := account.Address

	// Create a signer that delegates to the keystore
	return &KeystoreSigner{
		privateKeySigner: nil, // We'll handle signing through keystore
		keystorePath:     keystorePath,
		address:          address,
		keyStore:         ks,
		account:          account,
		password:         NewSecureBytesFromString(password),
	}, nil
}

// NewKeystoreSignerFromDirectory creates a new KeystoreSigner by finding and loading
// a keystore file from a directory. It loads the first keystore file found.
// Parameters:
//   - keystoreDir: Directory containing keystore files
//   - password: Password to decrypt the keystore file
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred during loading or decryption
func NewKeystoreSignerFromDirectory(keystoreDir, password string) (*KeystoreSigner, error) {
	if keystoreDir == "" {
		return nil, fmt.Errorf("keystore directory cannot be empty")
	}

	// List all files in the directory
	files, err := os.ReadDir(keystoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore directory: %w", err)
	}

	// Find the first keystore file (files starting with UTC--)
	var keystoreFile string
	for _, file := range files {
		if !file.IsDir() && len(file.Name()) > 3 && file.Name()[:3] == "UTC" {
			keystoreFile = filepath.Join(keystoreDir, file.Name())
			break
		}
	}

	if keystoreFile == "" {
		return nil, fmt.Errorf("no keystore files found in directory")
	}

	return NewKeystoreSigner(keystoreFile, password)
}

// CreateKeystore creates a new keystore file with a randomly generated private key
// Parameters:
//   - keystoreDir: Directory to create the keystore file in
//   - password: Password to encrypt the keystore file
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - string: Path to the created keystore file
//   - error: Any error that occurred during creation
func CreateKeystore(keystoreDir, password string) (*KeystoreSigner, string, error) {
	if keystoreDir == "" {
		return nil, "", fmt.Errorf("keystore directory cannot be empty")
	}

	// Create the keystore directory if it doesn't exist
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// Create a new keystore
	ks := keystore.NewKeyStore(keystoreDir, keystore.StandardScryptN, keystore.StandardScryptP)

	// Create a new account
	account, err := ks.NewAccount(password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create new account: %w", err)
	}

	// Create the signer using the keystore
	signer := &KeystoreSigner{
		privateKeySigner: nil,
		keystorePath:     account.URL.Path,
		address:          account.Address,
		keyStore:         ks,
		account:          account,
		password:         NewSecureBytesFromString(password),
	}

	return signer, account.URL.Path, nil
}

// GetKeystorePath returns the path to the keystore file
func (s *KeystoreSigner) GetKeystorePath() string {
	return s.keystorePath
}

// PersonalSign implements personal_sign (EIP-191 version 0x45)
// It prepends "\x19Ethereum Signed Message:\n" + len(message) to the message before signing
func (s *KeystoreSigner) PersonalSign(data string) ([]byte, error) {
	// Create the personal sign message format
	// "\x19Ethereum Signed Message:\n" + len(message) + message
	messageBytes := []byte(data)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes)))
	prefixedMessage := append(prefix, messageBytes...)

	// Hash the prefixed message
	hash := crypto.Keccak256Hash(prefixedMessage)

	// Sign using the keystore
	signature, err := s.keyStore.SignHashWithPassphrase(s.account, string(s.password.Bytes()), hash.Bytes())
	if err != nil {
		return nil, err
	}
	
	// keystore.SignHashWithPassphrase returns signature with V in [0,1] range
	// We need to adjust it to Ethereum's [27,28] range
	return NormalizeSignatureV(signature), nil
}

// SignEIP191Message signs an EIP-191 formatted message
func (s *KeystoreSigner) SignEIP191Message(message string) ([]byte, error) {
	// Validate EIP-191 message format
	messageBytes := []byte(message)
	err := ValidateEIP191Message(messageBytes)
	if err != nil {
		return nil, err
	}

	// For EIP-191 messages, we sign the raw message bytes
	hash := crypto.Keccak256Hash(messageBytes)
	signature, err := s.keyStore.SignHashWithPassphrase(s.account, string(s.password.Bytes()), hash.Bytes())
	if err != nil {
		return nil, err
	}
	
	// keystore.SignHashWithPassphrase returns signature with V in [0,1] range
	// We need to adjust it to Ethereum's [27,28] range
	if len(signature) == 65 && signature[64] < 27 {
		signature[64] += 27
	}
	
	return signature, nil
}

// SignRawMessage signs raw message bytes
func (s *KeystoreSigner) SignRawMessage(raw []byte) ([]byte, error) {
	hash := crypto.Keccak256Hash(raw)
	signature, err := s.keyStore.SignHashWithPassphrase(s.account, string(s.password.Bytes()), hash.Bytes())
	if err != nil {
		return nil, err
	}
	
	// keystore.SignHashWithPassphrase returns signature with V in [0,1] range
	// We need to adjust it to Ethereum's [27,28] range
	if len(signature) == 65 && signature[64] < 27 {
		signature[64] += 27
	}
	
	return signature, nil
}

// SignHash signs the hashed data using the private key
func (s *KeystoreSigner) SignHash(hashedData common.Hash) ([]byte, error) {
	signature, err := s.keyStore.SignHashWithPassphrase(s.account, string(s.password.Bytes()), hashedData.Bytes())
	if err != nil {
		return nil, err
	}
	
	// keystore.SignHashWithPassphrase returns signature with V in [0,1] range
	// We need to adjust it to Ethereum's [27,28] range
	if len(signature) == 65 && signature[64] < 27 {
		signature[64] += 27
	}
	
	return signature, nil
}

// SignTypedData implements EIP-712 typed data signing
func (s *KeystoreSigner) SignTypedData(typedData eip712.TypedData) ([]byte, error) {
	// Use the flexible helper function that works with any HashSigner
	return SignTypedDataWithHash(s, typedData)
}

// GetAddress returns the Ethereum address associated with the private key
// Implements AddressGetter interface
func (s *KeystoreSigner) GetAddress() common.Address {
	return s.address
}

// SignTransactionWithChainID signs an Ethereum transaction with the private key
// Implements TransactionSigner interface
// IMPORTANT: Always uses the provided chainID for signing, NOT tx.ChainId()
func (s *KeystoreSigner) SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("transaction is nil")
	}

	if chainID == nil {
		return nil, fmt.Errorf("chainID is nil")
	}

	return s.keyStore.SignTxWithPassphrase(s.account, string(s.password.Bytes()), tx, chainID)
}

// ExportPrivateKey exports the private key in hex format
// WARNING: This exposes the private key in plain text. Use with caution.
// Note: With the current keystore-based implementation, we cannot directly export the private key
// as the keystore doesn't provide a method to extract the private key in plain text.
func (s *KeystoreSigner) ExportPrivateKey() (string, error) {
	return "", fmt.Errorf("private key export not supported with keystore-based implementation")
}

// Close securely cleans up sensitive data from memory
// This should be called when the signer is no longer needed
func (s *KeystoreSigner) Close() {
	if s.password != nil {
		s.password.Zeroize()
		s.password = nil
	}
}

// createTestKeystore creates a test keystore file for testing purposes
// This is an internal helper function and should not be exported
func createTestKeystore(keystoreDir, password string) (string, common.Address, error) {
	// Generate a new private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", common.Address{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create the keystore directory if it doesn't exist
	if err := os.MkdirAll(keystoreDir, 0700); err != nil {
		return "", common.Address{}, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// Create a new keystore
	ks := keystore.NewKeyStore(keystoreDir, keystore.LightScryptN, keystore.LightScryptP)

	// Import the private key
	account, err := ks.ImportECDSA(privateKey, password)
	if err != nil {
		return "", common.Address{}, fmt.Errorf("failed to import private key: %w", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return account.URL.Path, address, nil
}