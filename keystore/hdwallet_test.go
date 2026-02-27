package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tyler-smith/go-bip39"
)

// Known test vector: BIP-39 "abandon" mnemonic (128-bit entropy, all zeros)
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Expected first derived address for the test mnemonic at m/44'/60'/0'/0/0
// This is a well-known test vector.
var testExpectedAddress = common.HexToAddress("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

var testPassword = []byte("test-password-123")

func TestCreateHDWallet(t *testing.T) {
	dir := t.TempDir()

	address, walletPath, err := CreateHDWallet(dir, testPassword, 128)
	if err != nil {
		t.Fatalf("CreateHDWallet failed: %v", err)
	}

	if address == "" {
		t.Error("address should not be empty")
	}

	if !common.IsHexAddress(address) {
		t.Errorf("address is not valid hex: %s", address)
	}

	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		t.Errorf("HD wallet file does not exist at %s", walletPath)
	}

	expectedPath := filepath.Join(dir, hdwalletFileName(address))
	if walletPath != expectedPath {
		t.Errorf("wallet path = %q, want %q", walletPath, expectedPath)
	}
}

func TestImportHDWallet_AlreadyExists(t *testing.T) {
	dir := t.TempDir()

	_, _, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("first ImportHDWallet failed: %v", err)
	}

	_, _, err = ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err == nil {
		t.Fatal("expected error for duplicate HD wallet, got nil")
	}
}

func TestCreateHDWallet_EmptyDir(t *testing.T) {
	_, _, err := CreateHDWallet("", testPassword, 128)
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestCreateHDWallet_EmptyPassword(t *testing.T) {
	dir := t.TempDir()
	_, _, err := CreateHDWallet(dir, nil, 128)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestCreateHDWallet_InvalidEntropy(t *testing.T) {
	dir := t.TempDir()
	_, _, err := CreateHDWallet(dir, testPassword, 100)
	if err == nil {
		t.Fatal("expected error for invalid entropy bits")
	}
}

func TestImportHDWallet(t *testing.T) {
	dir := t.TempDir()

	address, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	if address != testExpectedAddress.Hex() {
		t.Errorf("address = %s, want %s", address, testExpectedAddress.Hex())
	}

	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		t.Errorf("HD wallet file does not exist at %s", walletPath)
	}

	expectedPath := filepath.Join(dir, hdwalletFileName(address))
	if walletPath != expectedPath {
		t.Errorf("wallet path = %q, want %q", walletPath, expectedPath)
	}
}

func TestImportHDWallet_InvalidMnemonic(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ImportHDWallet(dir, []byte("invalid mnemonic words that are not valid"), testPassword)
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

func TestOpenHDWallet(t *testing.T) {
	dir := t.TempDir()
	_, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	wallet, err := OpenHDWallet(walletPath, testPassword)
	if err != nil {
		t.Fatalf("OpenHDWallet failed: %v", err)
	}
	defer wallet.Close()

	addr, err := wallet.DeriveAddress(0)
	if err != nil {
		t.Fatalf("DeriveAddress failed: %v", err)
	}

	if addr != testExpectedAddress {
		t.Errorf("derived address = %s, want %s", addr.Hex(), testExpectedAddress.Hex())
	}
}

func TestOpenHDWallet_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	_, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	_, err = OpenHDWallet(walletPath, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExportMnemonic(t *testing.T) {
	dir := t.TempDir()
	_, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	exported, err := ExportMnemonic(walletPath, testPassword)
	if err != nil {
		t.Fatalf("ExportMnemonic failed: %v", err)
	}
	defer SecureZeroize(exported)

	if string(exported) != testMnemonic {
		t.Errorf("exported mnemonic = %q, want %q", string(exported), testMnemonic)
	}
}

func TestVerifyHDWalletPassword(t *testing.T) {
	dir := t.TempDir()
	_, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	if err := VerifyHDWalletPassword(walletPath, testPassword); err != nil {
		t.Fatalf("VerifyHDWalletPassword failed: %v", err)
	}

	if err := VerifyHDWalletPassword(walletPath, []byte("wrong-password")); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestExportMnemonic_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	_, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	_, err = ExportMnemonic(walletPath, []byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestHDWallet_DeriveAddresses(t *testing.T) {
	seed := bip39.NewSeed(testMnemonic, "")
	defer SecureZeroize(seed)

	basePath, err := accounts.ParseDerivationPath(defaultBasePath)
	if err != nil {
		t.Fatalf("ParseDerivationPath failed: %v", err)
	}

	wallet, err := NewHDWallet(seed, basePath)
	if err != nil {
		t.Fatalf("NewHDWallet failed: %v", err)
	}
	defer wallet.Close()

	addresses, err := wallet.DeriveAddresses(0, 5)
	if err != nil {
		t.Fatalf("DeriveAddresses failed: %v", err)
	}

	if len(addresses) != 5 {
		t.Fatalf("expected 5 addresses, got %d", len(addresses))
	}

	// First address must match test vector
	if addresses[0] != testExpectedAddress {
		t.Errorf("addresses[0] = %s, want %s", addresses[0].Hex(), testExpectedAddress.Hex())
	}

	// All addresses must be unique
	seen := make(map[common.Address]bool)
	for i, addr := range addresses {
		if seen[addr] {
			t.Errorf("duplicate address at index %d: %s", i, addr.Hex())
		}
		seen[addr] = true
	}
}

func TestHDWallet_DeriveAddresses_InvalidRange(t *testing.T) {
	seed := bip39.NewSeed(testMnemonic, "")
	defer SecureZeroize(seed)

	basePath, err := accounts.ParseDerivationPath(defaultBasePath)
	if err != nil {
		t.Fatalf("ParseDerivationPath failed: %v", err)
	}

	wallet, err := NewHDWallet(seed, basePath)
	if err != nil {
		t.Fatalf("NewHDWallet failed: %v", err)
	}
	defer wallet.Close()

	// start >= end
	_, err = wallet.DeriveAddresses(5, 5)
	if err != ErrInvalidDerivationRange {
		t.Errorf("expected ErrInvalidDerivationRange, got %v", err)
	}

	_, err = wallet.DeriveAddresses(5, 3)
	if err != ErrInvalidDerivationRange {
		t.Errorf("expected ErrInvalidDerivationRange, got %v", err)
	}
}

func TestHDWallet_CloseAndUse(t *testing.T) {
	seed := bip39.NewSeed(testMnemonic, "")
	defer SecureZeroize(seed)

	basePath, err := accounts.ParseDerivationPath(defaultBasePath)
	if err != nil {
		t.Fatalf("ParseDerivationPath failed: %v", err)
	}

	wallet, err := NewHDWallet(seed, basePath)
	if err != nil {
		t.Fatalf("NewHDWallet failed: %v", err)
	}

	if err := wallet.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = wallet.DeriveAddress(0)
	if err != ErrHDWalletClosed {
		t.Errorf("expected ErrHDWalletClosed after Close, got %v", err)
	}

	_, err = wallet.DeriveKey(0)
	if err != ErrHDWalletClosed {
		t.Errorf("expected ErrHDWalletClosed after Close, got %v", err)
	}
}

func TestGetHDWalletInfo(t *testing.T) {
	dir := t.TempDir()
	address, walletPath, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	info, err := GetHDWalletInfo(walletPath)
	if err != nil {
		t.Fatalf("GetHDWalletInfo failed: %v", err)
	}

	if info.PrimaryAddress != address {
		t.Errorf("PrimaryAddress = %s, want %s", info.PrimaryAddress, address)
	}

	if info.BasePath != defaultBasePath {
		t.Errorf("BasePath = %s, want %s", info.BasePath, defaultBasePath)
	}

	if info.Path != walletPath {
		t.Errorf("Path = %s, want %s", info.Path, walletPath)
	}
}

func TestListHDWallets(t *testing.T) {
	dir := t.TempDir()

	// Empty directory
	wallets, err := ListHDWallets(dir)
	if err != nil {
		t.Fatalf("ListHDWallets failed: %v", err)
	}
	if len(wallets) != 0 {
		t.Errorf("expected 0 wallets, got %d", len(wallets))
	}

	// Import one wallet
	address, _, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("ImportHDWallet failed: %v", err)
	}

	wallets, err = ListHDWallets(dir)
	if err != nil {
		t.Fatalf("ListHDWallets failed: %v", err)
	}
	if len(wallets) != 1 {
		t.Fatalf("expected 1 wallet, got %d", len(wallets))
	}
	if wallets[0].PrimaryAddress != address {
		t.Errorf("PrimaryAddress = %s, want %s", wallets[0].PrimaryAddress, address)
	}
}

func TestListHDWallets_Multiple(t *testing.T) {
	dir := t.TempDir()

	_, _, err := ImportHDWallet(dir, []byte(testMnemonic), testPassword)
	if err != nil {
		t.Fatalf("first ImportHDWallet failed: %v", err)
	}

	_, _, err = CreateHDWallet(dir, testPassword, 128)
	if err != nil {
		t.Fatalf("CreateHDWallet failed: %v", err)
	}

	wallets, err := ListHDWallets(dir)
	if err != nil {
		t.Fatalf("ListHDWallets failed: %v", err)
	}
	if len(wallets) != 2 {
		t.Fatalf("expected 2 wallets, got %d", len(wallets))
	}

	// All addresses must be unique
	if wallets[0].PrimaryAddress == wallets[1].PrimaryAddress {
		t.Error("expected different addresses for different wallets")
	}
}

func TestCreateHDWalletRoundTrip(t *testing.T) {
	dir := t.TempDir()

	address, walletPath, err := CreateHDWallet(dir, testPassword, 128)
	if err != nil {
		t.Fatalf("CreateHDWallet failed: %v", err)
	}

	wallet, err := OpenHDWallet(walletPath, testPassword)
	if err != nil {
		t.Fatalf("OpenHDWallet failed: %v", err)
	}
	defer wallet.Close()

	derivedAddr, err := wallet.DeriveAddress(0)
	if err != nil {
		t.Fatalf("DeriveAddress failed: %v", err)
	}

	if derivedAddr.Hex() != address {
		t.Errorf("round-trip address mismatch: CreateHDWallet returned %s, DeriveAddress(0) returned %s", address, derivedAddr.Hex())
	}
}
