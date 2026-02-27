package keystore

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

const (
	hdwalletVersion    = 1
	hdwalletFilePrefix = "hdwallet--"
	hdwalletFileSuffix = ".json"
	defaultBasePath    = "m/44'/60'/0'/0"
	defaultLocale      = "en"
	defaultScryptN     = keystore.StandardScryptN
	defaultScryptP     = keystore.StandardScryptP
)

// HDWalletFile represents the encrypted HD wallet file on disk.
type HDWalletFile struct {
	Version        int                 `json:"version"`
	PrimaryAddress string              `json:"primary_address"`
	Mnemonic       keystore.CryptoJSON `json:"mnemonic"`
	HDConfig       HDConfig            `json:"hd_config"`
}

// HDConfig stores the HD derivation configuration.
type HDConfig struct {
	BasePath string `json:"base_path"`
	Locale   string `json:"locale"`
}

// HDWalletInfo contains non-secret HD wallet metadata readable without decryption.
type HDWalletInfo struct {
	PrimaryAddress string
	BasePath       string
	Path           string
}

// HDWallet derives Ethereum keys from a BIP-39 seed held in memory.
type HDWallet struct {
	seed     *SecureBytes
	basePath accounts.DerivationPath
	closed   bool
}

// CreateHDWallet generates a random BIP-39 mnemonic, encrypts its entropy,
// derives the primary address (index 0), and writes an hdwallet--<address>.json file into dir.
func CreateHDWallet(dir string, password []byte, entropyBits int) (address, walletPath string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}
	if entropyBits != 128 && entropyBits != 160 && entropyBits != 192 && entropyBits != 224 && entropyBits != 256 {
		return "", "", fmt.Errorf("invalid entropy bits: must be 128, 160, 192, 224, or 256")
	}

	entropy, err := bip39.NewEntropy(entropyBits)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	defer SecureZeroize(entropy)

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}
	defer zeroString(&mnemonic)

	return writeHDWalletFile(dir, []byte(mnemonic), entropy, password)
}

// ImportHDWallet validates the provided mnemonic, encrypts its entropy, and
// writes an hdwallet--<address>.json file into dir.
func ImportHDWallet(dir string, mnemonic []byte, password []byte) (address, walletPath string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("directory cannot be empty")
	}
	if len(mnemonic) == 0 {
		return "", "", fmt.Errorf("mnemonic cannot be empty")
	}
	if len(password) == 0 {
		return "", "", ErrEmptyPassword
	}

	mnemonicStr := strings.TrimSpace(string(mnemonic))
	if !bip39.IsMnemonicValid(mnemonicStr) {
		return "", "", ErrMnemonicInvalid
	}

	entropy, err := bip39.EntropyFromMnemonic(mnemonicStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to extract entropy from mnemonic: %w", err)
	}
	defer SecureZeroize(entropy)

	return writeHDWalletFile(dir, []byte(mnemonicStr), entropy, password)
}

// OpenHDWallet decrypts an HD wallet file and returns an HDWallet ready for key derivation.
func OpenHDWallet(walletPath string, password []byte) (*HDWallet, error) {
	if walletPath == "" {
		return nil, fmt.Errorf("HD wallet path cannot be empty")
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}

	wf, err := readHDWalletFile(walletPath)
	if err != nil {
		return nil, err
	}

	if wf.Version != hdwalletVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrHDWalletInvalidVersion, wf.Version, hdwalletVersion)
	}

	entropy, err := keystore.DecryptDataV3(wf.Mnemonic, string(password))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHDWalletDecryptFailed, err)
	}
	defer SecureZeroize(entropy)

	mnemonicStr, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct mnemonic from entropy: %w", err)
	}
	defer zeroString(&mnemonicStr)

	seed := bip39.NewSeed(mnemonicStr, "")
	defer SecureZeroize(seed) // NewSecureBytes copies, so original must be zeroized

	basePath, err := accounts.ParseDerivationPath(wf.HDConfig.BasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base path %q: %w", wf.HDConfig.BasePath, err)
	}

	return &HDWallet{
		seed:     NewSecureBytes(seed),
		basePath: basePath,
	}, nil
}

// VerifyHDWalletPassword verifies that the password can decrypt the HD wallet
// without returning any secret material.
func VerifyHDWalletPassword(walletPath string, password []byte) error {
	if walletPath == "" {
		return fmt.Errorf("HD wallet path cannot be empty")
	}
	if len(password) == 0 {
		return ErrEmptyPassword
	}

	wf, err := readHDWalletFile(walletPath)
	if err != nil {
		return err
	}

	if wf.Version != hdwalletVersion {
		return fmt.Errorf("%w: got %d, expected %d", ErrHDWalletInvalidVersion, wf.Version, hdwalletVersion)
	}

	entropy, err := keystore.DecryptDataV3(wf.Mnemonic, string(password))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHDWalletDecryptFailed, err)
	}
	SecureZeroize(entropy)
	return nil
}

// ExportMnemonic decrypts the HD wallet and returns the mnemonic words.
// The caller is responsible for securely zeroizing the returned bytes.
func ExportMnemonic(walletPath string, password []byte) ([]byte, error) {
	if walletPath == "" {
		return nil, fmt.Errorf("HD wallet path cannot be empty")
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}

	wf, err := readHDWalletFile(walletPath)
	if err != nil {
		return nil, err
	}

	if wf.Version != hdwalletVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrHDWalletInvalidVersion, wf.Version, hdwalletVersion)
	}

	entropy, err := keystore.DecryptDataV3(wf.Mnemonic, string(password))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHDWalletDecryptFailed, err)
	}
	defer SecureZeroize(entropy)

	mnemonicStr, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct mnemonic from entropy: %w", err)
	}
	defer zeroString(&mnemonicStr)

	return []byte(mnemonicStr), nil
}

// GetHDWalletInfo reads HD wallet metadata without requiring a password.
func GetHDWalletInfo(walletPath string) (*HDWalletInfo, error) {
	if walletPath == "" {
		return nil, fmt.Errorf("HD wallet path cannot be empty")
	}

	wf, err := readHDWalletFile(walletPath)
	if err != nil {
		return nil, err
	}

	return &HDWalletInfo{
		PrimaryAddress: wf.PrimaryAddress,
		BasePath:       wf.HDConfig.BasePath,
		Path:           walletPath,
	}, nil
}

// NewHDWallet constructs an HDWallet from a raw BIP-39 seed and base derivation path.
func NewHDWallet(seed []byte, basePath accounts.DerivationPath) (*HDWallet, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("seed cannot be empty")
	}
	if len(basePath) == 0 {
		return nil, fmt.Errorf("base path cannot be empty")
	}

	return &HDWallet{
		seed:     NewSecureBytes(seed),
		basePath: basePath,
	}, nil
}

// DeriveAddress derives the Ethereum address at basePath/index.
func (w *HDWallet) DeriveAddress(index uint32) (common.Address, error) {
	key, err := w.DeriveKey(index)
	if err != nil {
		return common.Address{}, err
	}
	defer zeroPrivateKey(key)

	return crypto.PubkeyToAddress(key.PublicKey), nil
}

// DeriveKey derives the private key at basePath/index.
// The caller must zeroize the returned key when done.
func (w *HDWallet) DeriveKey(index uint32) (*ecdsa.PrivateKey, error) {
	if w.closed {
		return nil, ErrHDWalletClosed
	}

	seedBytes := w.seed.Bytes()
	defer SecureZeroize(seedBytes)

	masterKey, err := bip32.NewMasterKey(seedBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create master key: %v", ErrHDDerivationFailed, err)
	}
	defer zeroBIP32Key(masterKey)

	// Derive along the base path components; track intermediates for zeroization
	intermediateKeys := make([]*bip32.Key, 0, len(w.basePath))
	currentKey := masterKey
	for _, component := range w.basePath {
		childKey, err := currentKey.NewChildKey(component)
		if err != nil {
			for _, k := range intermediateKeys {
				zeroBIP32Key(k)
			}
			return nil, fmt.Errorf("%w: failed to derive child at component %d: %v", ErrHDDerivationFailed, component, err)
		}
		intermediateKeys = append(intermediateKeys, childKey)
		currentKey = childKey
	}
	defer func() {
		for _, k := range intermediateKeys {
			zeroBIP32Key(k)
		}
	}()

	// Derive the final index
	finalKey, err := currentKey.NewChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive child at index %d: %v", ErrHDDerivationFailed, index, err)
	}
	defer zeroBIP32Key(finalKey)

	// bip32 Key.Key is 33 bytes for private keys (leading 0x00 + 32 bytes)
	rawKey := finalKey.Key
	if len(rawKey) == 33 && rawKey[0] == 0x00 {
		rawKey = rawKey[1:]
	}

	privateKey, err := crypto.ToECDSA(rawKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse derived key: %v", ErrHDDerivationFailed, err)
	}

	return privateKey, nil
}

// DeriveAddresses batch-derives addresses for indices [start, end).
func (w *HDWallet) DeriveAddresses(start, end uint32) ([]common.Address, error) {
	if start >= end {
		return nil, ErrInvalidDerivationRange
	}

	addresses := make([]common.Address, 0, end-start)
	for i := start; i < end; i++ {
		addr, err := w.DeriveAddress(i)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

// Close zeroizes the seed, rendering the wallet unusable.
func (w *HDWallet) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.seed != nil {
		w.seed.Zeroize()
	}
	return nil
}

// --- internal helpers ---

var (
	ErrHDWalletAlreadyExists  = fmt.Errorf("HD wallet already exists")
	ErrHDWalletNotFound       = fmt.Errorf("HD wallet file not found")
	ErrHDWalletDecryptFailed  = fmt.Errorf("HD wallet decryption failed")
	ErrHDWalletInvalidVersion = fmt.Errorf("unsupported HD wallet version")
	ErrMnemonicInvalid        = fmt.Errorf("invalid BIP-39 mnemonic")
	ErrHDWalletClosed         = fmt.Errorf("HD wallet is closed")
	ErrHDDerivationFailed     = fmt.Errorf("HD key derivation failed")
	ErrInvalidDerivationRange = fmt.Errorf("invalid derivation range: start must be less than end")
)

// SecureBytes wraps sensitive byte data with zeroization support.
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a SecureBytes from a copy of data.
func NewSecureBytes(data []byte) *SecureBytes {
	sb := &SecureBytes{data: make([]byte, len(data))}
	copy(sb.data, data)
	return sb
}

// Bytes returns a copy of the underlying data.
func (sb *SecureBytes) Bytes() []byte {
	if sb == nil || sb.data == nil {
		return nil
	}
	out := make([]byte, len(sb.data))
	copy(out, sb.data)
	return out
}

// Zeroize overwrites the data with zeros.
func (sb *SecureBytes) Zeroize() {
	if sb == nil || sb.data == nil {
		return
	}
	SecureZeroize(sb.data)
	sb.data = nil
}

// ListHDWallets scans dir for HD wallet files and returns their metadata.
func ListHDWallets(dir string) ([]HDWalletInfo, error) {
	if dir == "" {
		return nil, fmt.Errorf("directory cannot be empty")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var wallets []HDWalletInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, hdwalletFilePrefix) || !strings.HasSuffix(name, hdwalletFileSuffix) {
			continue
		}

		path := filepath.Join(dir, name)
		info, err := GetHDWalletInfo(path)
		if err != nil {
			continue // skip unreadable files
		}
		wallets = append(wallets, *info)
	}
	return wallets, nil
}

// hdwalletFileName returns the filename for an HD wallet with the given address.
func hdwalletFileName(address string) string {
	return hdwalletFilePrefix + strings.ToLower(address) + hdwalletFileSuffix
}

func writeHDWalletFile(dir string, mnemonicBytes, entropy, password []byte) (string, string, error) {
	mnemonicStr := string(mnemonicBytes)

	// Derive primary address (index 0)
	seed := bip39.NewSeed(mnemonicStr, "")
	defer SecureZeroize(seed)

	basePath, err := accounts.ParseDerivationPath(defaultBasePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse default base path: %w", err)
	}

	wallet, err := NewHDWallet(seed, basePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create HD wallet: %w", err)
	}
	defer wallet.Close()

	primaryAddr, err := wallet.DeriveAddress(0)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive primary address: %w", err)
	}

	walletPath := filepath.Join(dir, hdwalletFileName(primaryAddr.Hex()))

	// Encrypt entropy
	cryptoJSON, err := keystore.EncryptDataV3(entropy, password, defaultScryptN, defaultScryptP)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt HD wallet: %w", err)
	}

	wf := HDWalletFile{
		Version:        hdwalletVersion,
		PrimaryAddress: primaryAddr.Hex(),
		Mnemonic:       cryptoJSON,
		HDConfig: HDConfig{
			BasePath: defaultBasePath,
			Locale:   defaultLocale,
		},
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal HD wallet: %w", err)
	}

	f, err := os.OpenFile(walletPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return "", "", fmt.Errorf("%w: %s", ErrHDWalletAlreadyExists, walletPath)
		}
		return "", "", fmt.Errorf("failed to create HD wallet file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(walletPath)
		return "", "", fmt.Errorf("failed to write HD wallet file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close HD wallet file: %w", err)
	}

	return primaryAddr.Hex(), walletPath, nil
}

func readHDWalletFile(walletPath string) (*HDWalletFile, error) {
	data, err := os.ReadFile(walletPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrHDWalletNotFound, walletPath)
		}
		return nil, fmt.Errorf("failed to read HD wallet file: %w", err)
	}

	var wf HDWalletFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("failed to parse HD wallet file: %w", err)
	}

	return &wf, nil
}

// zeroBIP32Key zeroizes the sensitive fields of a bip32.Key.
func zeroBIP32Key(k *bip32.Key) {
	if k == nil {
		return
	}
	SecureZeroize(k.Key)
	SecureZeroize(k.ChainCode)
}

// zeroString attempts to overwrite a string's backing memory.
// Go strings are immutable so this is best-effort.
func zeroString(s *string) {
	if s == nil {
		return
	}
	*s = ""
}
