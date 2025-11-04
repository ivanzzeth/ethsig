package ethsig

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

var (
	// Verify EthPrivateKeySigner implements all required interfaces
	_ AddressGetter     = (*EthPrivateKeySigner)(nil)
	_ HashSigner        = (*EthPrivateKeySigner)(nil)
	_ EIP191Signer      = (*EthPrivateKeySigner)(nil)
	_ PersonalSigner    = (*EthPrivateKeySigner)(nil)
	_ TypedDataSigner   = (*EthPrivateKeySigner)(nil)
	_ TransactionSigner = (*EthPrivateKeySigner)(nil)
)

// EthPrivateKeySigner implements Signer using an Ethereum private key
type EthPrivateKeySigner struct {
	privateKey *ecdsa.PrivateKey
}

// NewEthPrivateKeySigner creates a new EthPrivateKeySigner instance
func NewEthPrivateKeySigner(privateKey *ecdsa.PrivateKey) *EthPrivateKeySigner {
	return &EthPrivateKeySigner{
		privateKey: privateKey,
	}
}

func NewEthPrivateKeySignerFromPrivateKeyHex(privateKeyHex string) (*EthPrivateKeySigner, error) {
	priv, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, err
	}

	return &EthPrivateKeySigner{
		privateKey: priv,
	}, nil
}

// PersonalSign implements personal_sign (EIP-191 version 0x45)
// It prepends "\x19Ethereum Signed Message:\n" + len(message) to the message before signing
// This implementation uses the composable PersonalSignWithHash helper
func (s *EthPrivateKeySigner) PersonalSign(data string) ([]byte, error) {
	return PersonalSignWithHash(s, data)
}

func (s *EthPrivateKeySigner) SignEIP191Message(message string) ([]byte, error) {
	return SignEIP191MessageWithRawMessageSigner(s, message)
}

func (s *EthPrivateKeySigner) SignRawMessage(raw []byte) ([]byte, error) {
	return SignRawMessageWithHashSigner(s, raw)
}

// Sign signs the hashed data using the private key
func (s *EthPrivateKeySigner) SignHash(hashedData common.Hash) ([]byte, error) {
	sign, err := crypto.Sign(hashedData.Bytes(), s.privateKey)
	if err != nil {
		return nil, err
	}

	// Adjust V value for Ethereum signatures (27 or 28)
	return NormalizeSignatureV(sign), err
}

// SignTypedData implements EIP-712 typed data signing
// This implementation uses the composable SignTypedDataWithHash helper
func (s *EthPrivateKeySigner) SignTypedData(typedData eip712.TypedData) ([]byte, error) {
	return SignTypedDataWithHash(s, typedData)
}

// GetAddress returns the Ethereum address associated with the private key
// Implements AddressGetter interface
func (s *EthPrivateKeySigner) GetAddress() common.Address {
	publicKey := s.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		// This should never happen with a valid private key
		return common.Address{}
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA)
}

// SignTransactionWithChainID signs an Ethereum transaction with the private key
// Implements TransactionSigner interface
// IMPORTANT: Always uses the provided chainID for signing, NOT tx.ChainId()
// This ensures correct signing even when tx.ChainId() returns unexpected values
// (e.g., MaxUint64 for unsigned legacy transactions)
//
// Parameters:
//   - tx: The transaction to sign (must have nonce, gas, gasPrice, etc. set)
//   - chainID: The explicit chain ID to use for signing (e.g., 137 for Polygon)
func (s *EthPrivateKeySigner) SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx == nil {
		return nil, NewTransactionError("transaction is nil", nil)
	}

	if chainID == nil {
		return nil, NewTransactionError("chainID is nil", nil)
	}

	// Create a signer using LatestSignerForChainID which automatically selects
	// the appropriate signer based on transaction type (Legacy, EIP-2930, or EIP-1559)
	// IMPORTANT: Always use the explicit chainID parameter, not tx.ChainId()
	signer := types.LatestSignerForChainID(chainID)

	// Sign the transaction
	signedTx, err := types.SignTx(tx, signer, s.privateKey)
	if err != nil {
		return nil, NewTransactionError("failed to sign transaction", err)
	}

	return signedTx, nil
}
