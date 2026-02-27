package ethsig

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/ivanzzeth/ethsig/keystore"
)

var (
	// Verify HDWalletSigner implements all required interfaces
	_ AddressGetter     = (*HDWalletSigner)(nil)
	_ RawMessageSigner  = (*HDWalletSigner)(nil)
	_ HashSigner        = (*HDWalletSigner)(nil)
	_ EIP191Signer      = (*HDWalletSigner)(nil)
	_ PersonalSigner    = (*HDWalletSigner)(nil)
	_ TypedDataSigner   = (*HDWalletSigner)(nil)
	_ TransactionSigner = (*HDWalletSigner)(nil)
)

// HDWalletSigner implements Signer using a key derived from an HD wallet at a
// specific derivation index. The private key is derived once at construction
// and held in memory until Close is called.
type HDWalletSigner struct {
	wallet     *keystore.HDWallet
	index      uint32
	address    common.Address
	privateKey *ecdsa.PrivateKey
}

// NewHDWalletSigner creates a new signer for the given HD wallet at the
// specified derivation index. The private key is derived immediately.
func NewHDWalletSigner(wallet *keystore.HDWallet, index uint32) (*HDWalletSigner, error) {
	if wallet == nil {
		return nil, NewSignerError("wallet cannot be nil", nil)
	}

	privateKey, err := wallet.DeriveKey(index)
	if err != nil {
		return nil, NewSignerError("failed to derive key", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &HDWalletSigner{
		wallet:     wallet,
		index:      index,
		address:    address,
		privateKey: privateKey,
	}, nil
}

// GetAddress returns the Ethereum address derived at this signer's index.
func (s *HDWalletSigner) GetAddress() common.Address {
	return s.address
}

// SignHash signs the hashed data using the derived private key.
func (s *HDWalletSigner) SignHash(hashedData common.Hash) ([]byte, error) {
	if s.privateKey == nil {
		return nil, NewSignerError("signer is closed", nil)
	}

	sig, err := crypto.Sign(hashedData.Bytes(), s.privateKey)
	if err != nil {
		return nil, err
	}

	return NormalizeSignatureV(sig), nil
}

// SignRawMessage signs raw message bytes by hashing them first.
func (s *HDWalletSigner) SignRawMessage(raw []byte) ([]byte, error) {
	return SignRawMessageWithHashSigner(s, raw)
}

// SignEIP191Message signs an EIP-191 formatted message.
func (s *HDWalletSigner) SignEIP191Message(message string) ([]byte, error) {
	return SignEIP191MessageWithRawMessageSigner(s, message)
}

// PersonalSign implements personal_sign (EIP-191 version 0x45).
func (s *HDWalletSigner) PersonalSign(data string) ([]byte, error) {
	return PersonalSignWithHash(s, data)
}

// SignTypedData implements EIP-712 typed data signing.
func (s *HDWalletSigner) SignTypedData(typedData eip712.TypedData) ([]byte, error) {
	return SignTypedDataWithHash(s, typedData)
}

// SignTransactionWithChainID signs an Ethereum transaction with the derived key.
func (s *HDWalletSigner) SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx == nil {
		return nil, NewTransactionError("transaction is nil", nil)
	}
	if chainID == nil {
		return nil, NewTransactionError("chainID is nil", nil)
	}
	if s.privateKey == nil {
		return nil, NewSignerError("signer is closed", nil)
	}

	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, s.privateKey)
	if err != nil {
		return nil, NewTransactionError("failed to sign transaction", err)
	}

	return signedTx, nil
}

// Close zeroizes the derived private key. The signer is unusable after this call.
func (s *HDWalletSigner) Close() error {
	if s.privateKey != nil {
		if s.privateKey.D != nil {
			s.privateKey.D.SetInt64(0)
		}
		s.privateKey = nil
	}
	return nil
}
