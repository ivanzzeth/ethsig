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
	_ RawMessageSigner  = (*KeystoreSigner)(nil)
	_ HashSigner        = (*KeystoreSigner)(nil)
	_ EIP191Signer      = (*KeystoreSigner)(nil)
	_ PersonalSigner    = (*KeystoreSigner)(nil)
	_ TypedDataSigner   = (*KeystoreSigner)(nil)
	_ TransactionSigner = (*KeystoreSigner)(nil)
)

// KeystoreScryptConfig holds the scrypt parameters for keystore encryption/decryption
type KeystoreScryptConfig struct {
	N int // CPU/memory cost parameter
	P int // Parallelization parameter
}

// Default scrypt configurations
var (
	// StandardScryptConfig uses standard scrypt parameters (high security, slower)
	StandardScryptConfig = KeystoreScryptConfig{
		N: keystore.StandardScryptN,
		P: keystore.StandardScryptP,
	}

	// LightScryptConfig uses light scrypt parameters (lower security, faster - suitable for testing)
	LightScryptConfig = KeystoreScryptConfig{
		N: keystore.LightScryptN,
		P: keystore.LightScryptP,
	}
)

// KeystoreSigner implements Signer using an Ethereum keystore
// It delegates all signing operations to the keystore's signing methods
// This allows external code to manage the KeyStore and create signers for specific addresses
type KeystoreSigner struct {
	keyStore *keystore.KeyStore

	address  common.Address
	account  accounts.Account
	password *SecureBytes
}

// NewKeystoreSigner creates a new KeystoreSigner from an existing KeyStore and address
// This is the recommended way to create KeystoreSigners when managing multiple accounts,
// as it allows external code to manage the KeyStore lifecycle and create signers for specific addresses.
//
// Parameters:
//   - ks: An existing KeyStore instance (managed by caller)
//   - address: The address to sign with (must exist in the KeyStore)
//   - password: Password to unlock the account
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred during account lookup or password validation
//
// Example:
//
//	// Create a single KeyStore for all accounts
//	ks := keystore.NewKeyStore("/path/to/keystore", keystore.StandardScryptN, keystore.StandardScryptP)
//
//	// Create signers for different addresses from the same KeyStore
//	addr1 := common.HexToAddress("0x1234...")
//	signer1, _ := ethsig.NewKeystoreSigner(ks, addr1, "password1")
//
//	addr2 := common.HexToAddress("0x5678...")
//	signer2, _ := ethsig.NewKeystoreSigner(ks, addr2, "password2")
func NewKeystoreSigner(ks *keystore.KeyStore, address common.Address, password string) (*KeystoreSigner, error) {
	account, err := ks.Find(accounts.Account{Address: address})
	if err != nil {
		return nil, err
	}

	// Validate password by attempting to unlock the account
	err = ks.Unlock(account, password)
	if err != nil {
		return nil, NewKeystoreError("failed to unlock account with provided password", err)
	}
	// Lock it again after validation
	ks.Lock(account.Address)

	// Create a signer that delegates to the keystore

	return &KeystoreSigner{
		keyStore: ks,
		address:  address,
		account:  account,
		password: NewSecureBytesFromString(password),
	}, nil
}

// NewKeystoreSignerFromPath creates a KeystoreSigner from a keystore directory/file path
// This is a convenience function that creates a new KeyStore internally.
//
// Parameters:
//   - keystorePath: Path to the keystore directory or file
//   - address: The address to sign with
//   - password: Password to unlock the account
//   - scryptConfig: Scrypt configuration (use nil for LightScryptConfig default)
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred
//
// Example:
//
//	addr := common.HexToAddress("0x1234...")
//	signer, err := ethsig.NewKeystoreSignerFromPath("/path/to/keystore", addr, "password", nil)
func NewKeystoreSignerFromPath(keystorePath string, address common.Address, password string, scryptConfig *KeystoreScryptConfig) (*KeystoreSigner, error) {
	if keystorePath == "" {
		return nil, NewKeystoreError("keystore path cannot be empty", nil)
	}

	// Use default config if not provided
	if scryptConfig == nil {
		scryptConfig = &LightScryptConfig
	}

	// Check if path is a file or directory
	info, err := os.Stat(keystorePath)
	if err != nil {
		return nil, NewKeystoreError("failed to access keystore path", err)
	}

	var keystoreDir string
	if info.IsDir() {
		// Path is a directory
		keystoreDir = keystorePath
	} else {
		// Path is a file, use its directory
		keystoreDir = filepath.Dir(keystorePath)
	}

	// Create a keystore instance
	ks := keystore.NewKeyStore(keystoreDir, scryptConfig.N, scryptConfig.P)

	// Use the main constructor
	return NewKeystoreSigner(ks, address, password)
}

// NewKeystoreSignerFromDirectory creates a KeystoreSigner from a directory and address
// This is a convenience wrapper around NewKeystoreSignerFromPath.
//
// Parameters:
//   - keystoreDir: Directory containing keystore files
//   - address: The address to sign with
//   - password: Password to unlock the account
//   - scryptConfig: Scrypt configuration (use nil for LightScryptConfig default)
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred
//
// Example:
//
//	addr := common.HexToAddress("0x1234...")
//	signer, err := ethsig.NewKeystoreSignerFromDirectory("/path/to/keystore", addr, "password", nil)
func NewKeystoreSignerFromDirectory(keystoreDir string, address common.Address, password string, scryptConfig *KeystoreScryptConfig) (*KeystoreSigner, error) {
	return NewKeystoreSignerFromPath(keystoreDir, address, password, scryptConfig)
}

// NewKeystoreSignerFromFile creates a KeystoreSigner from a specific keystore file and address
// This is a convenience wrapper around NewKeystoreSignerFromPath that validates the file exists.
//
// Parameters:
//   - keystoreFile: Path to a specific keystore file
//   - address: The address to sign with (must match the file's address)
//   - password: Password to unlock the account
//   - scryptConfig: Scrypt configuration (use nil for LightScryptConfig default)
//
// Returns:
//   - *KeystoreSigner: The initialized keystore signer
//   - error: Any error that occurred
//
// Example:
//
//	addr := common.HexToAddress("0x1234...")
//	signer, err := ethsig.NewKeystoreSignerFromFile("/path/to/keystore/UTC--2024...", addr, "password", nil)
func NewKeystoreSignerFromFile(keystoreFile string, address common.Address, password string, scryptConfig *KeystoreScryptConfig) (*KeystoreSigner, error) {
	// Validate the file exists and is not a directory
	info, err := os.Stat(keystoreFile)
	if err != nil {
		return nil, NewKeystoreError("keystore file not found", err)
	}
	if info.IsDir() {
		return nil, NewKeystoreError("path is a directory, expected a file", nil)
	}

	return NewKeystoreSignerFromPath(keystoreFile, address, password, scryptConfig)
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
	return NormalizeSignatureV(signature), nil
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
	return NormalizeSignatureV(signature), nil
}

// SignHash signs the hashed data using the private key
func (s *KeystoreSigner) SignHash(hashedData common.Hash) ([]byte, error) {
	signature, err := s.keyStore.SignHashWithPassphrase(s.account, string(s.password.Bytes()), hashedData.Bytes())
	if err != nil {
		return nil, err
	}

	// keystore.SignHashWithPassphrase returns signature with V in [0,1] range
	// We need to adjust it to Ethereum's [27,28] range
	return NormalizeSignatureV(signature), nil
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

// Close securely cleans up sensitive data from memory
// This should be called when the signer is no longer needed
func (s *KeystoreSigner) Close() error {
	if s.password != nil {
		s.password.Zeroize()
		s.password = nil
	}
	return nil
}
