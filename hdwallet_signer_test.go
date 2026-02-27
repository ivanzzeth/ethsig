package ethsig

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/tyler-smith/go-bip39"
)

const hdTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

var hdTestExpectedAddress = common.HexToAddress("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

func newTestHDWallet(t *testing.T) *keystore.HDWallet {
	t.Helper()
	seed := bip39.NewSeed(hdTestMnemonic, "")
	basePath, err := accounts.ParseDerivationPath("m/44'/60'/0'/0")
	if err != nil {
		t.Fatalf("ParseDerivationPath failed: %v", err)
	}
	wallet, err := keystore.NewHDWallet(seed, basePath)
	if err != nil {
		t.Fatalf("NewHDWallet failed: %v", err)
	}
	return wallet
}

func TestHDWalletSigner_SpecTestAllInterfaces(t *testing.T) {
	wallet := newTestHDWallet(t)
	defer wallet.Close()

	signer, err := NewHDWalletSigner(wallet, 0)
	if err != nil {
		t.Fatalf("NewHDWalletSigner failed: %v", err)
	}
	defer signer.Close()

	address := signer.GetAddress()
	if address != hdTestExpectedAddress {
		t.Fatalf("address = %s, want %s", address.Hex(), hdTestExpectedAddress.Hex())
	}

	SpecTestAllInterfaces(t, signer, address)
}

func TestHDWalletSigner_Close(t *testing.T) {
	wallet := newTestHDWallet(t)
	defer wallet.Close()

	signer, err := NewHDWalletSigner(wallet, 0)
	if err != nil {
		t.Fatalf("NewHDWalletSigner failed: %v", err)
	}

	if err := signer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Signing should fail after close
	_, err = signer.SignHash(common.Hash{})
	if err == nil {
		t.Error("expected error after Close, got nil")
	}

	_, err = signer.PersonalSign("test")
	if err == nil {
		t.Error("expected error after Close for PersonalSign, got nil")
	}
}

func TestHDWalletSigner_MultipleIndices(t *testing.T) {
	wallet := newTestHDWallet(t)
	defer wallet.Close()

	signer0, err := NewHDWalletSigner(wallet, 0)
	if err != nil {
		t.Fatalf("NewHDWalletSigner(0) failed: %v", err)
	}
	defer signer0.Close()

	signer1, err := NewHDWalletSigner(wallet, 1)
	if err != nil {
		t.Fatalf("NewHDWalletSigner(1) failed: %v", err)
	}
	defer signer1.Close()

	signer2, err := NewHDWalletSigner(wallet, 2)
	if err != nil {
		t.Fatalf("NewHDWalletSigner(2) failed: %v", err)
	}
	defer signer2.Close()

	// Addresses must be different
	addr0 := signer0.GetAddress()
	addr1 := signer1.GetAddress()
	addr2 := signer2.GetAddress()

	if addr0 == addr1 {
		t.Errorf("index 0 and 1 produced same address: %s", addr0.Hex())
	}
	if addr1 == addr2 {
		t.Errorf("index 1 and 2 produced same address: %s", addr1.Hex())
	}
	if addr0 == addr2 {
		t.Errorf("index 0 and 2 produced same address: %s", addr0.Hex())
	}

	// Signatures for the same message must be different
	msg := "test message for multiple signers"
	sig0, err := signer0.PersonalSign(msg)
	if err != nil {
		t.Fatalf("signer0.PersonalSign failed: %v", err)
	}
	sig1, err := signer1.PersonalSign(msg)
	if err != nil {
		t.Fatalf("signer1.PersonalSign failed: %v", err)
	}

	if string(sig0) == string(sig1) {
		t.Error("different indices should produce different signatures")
	}
}
