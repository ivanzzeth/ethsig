package ethsig

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethsig/eip712"
)

var ErrInvalidSignatureLen = errors.New("invalid signature length")
var ErrInvalidEIP191MessagePrefix = errors.New("invalid EIP191 message prefix")

type AddressGetter interface {
	// GetAddress returns the address associated with this signer
	GetAddress() common.Address
}

type RawMessageSigner interface {
	SignRawMessage(raw []byte) ([]byte, error)
}

type HashSigner interface {
	// SignHash signs the hashed data and returns the signature
	SignHash(hashedData common.Hash) ([]byte, error)
}

type EIP191Signer interface {
	SignEIP191Message(message string) ([]byte, error)
}

type PersonalSigner interface {
	PersonalSign(data string) ([]byte, error)
}

// TypedDataSigner is an interface for signing typed data
type TypedDataSigner interface {
	SignTypedData(typedData eip712.TypedData) ([]byte, error)
}

type TransactionSigner interface {
	SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

func SignHash(signer HashSigner, hashedData common.Hash) ([]byte, error) {
	return SignHashWithExactSigner(signer, hashedData)
}

// SignHashWithExactSigner is a helper function that signs hashed data using a HashSigner
func SignHashWithExactSigner(signer HashSigner, hashedData common.Hash) ([]byte, error) {
	return signer.SignHash(hashedData)
}

// SignEIP191Message flexibly signs an EIP-191 formatted message using the most appropriate method based on signer type
// It accepts any signer type and automatically chooses the best implementation:
// - If signer implements EIP191Signer, use SignEIP191Message directly
// This allows for maximum flexibility and future extensibility
func SignEIP191Message(signer any, message string) ([]byte, error) {
	// Try EIP191Signer
	if eip191, ok := signer.(EIP191Signer); ok {
		return eip191.SignEIP191Message(message)
	}

	if rawSigner, ok := signer.(RawMessageSigner); ok {
		return SignEIP191MessageWithRawMessageSigner(rawSigner, message)
	}

	return nil, fmt.Errorf("signer does not implement EIP191Signer")
}

// SignEIP191MessageWithExactSigner is a helper function that signs an EIP-191 formatted message
func SignEIP191MessageWithExactSigner(signer EIP191Signer, message string) ([]byte, error) {
	return signer.SignEIP191Message(message)
}

func SignEIP191MessageWithRawMessageSigner(signer RawMessageSigner, message string) ([]byte, error) {
	messageBytes := []byte(message)
	err := ValidateEIP191Message(messageBytes)
	if err != nil {
		return nil, err
	}

	return signer.SignRawMessage(messageBytes)
}

// PersonalSignWithExactSigner is a helper function that signs data using personal_sign (EIP-191 0x45)
func PersonalSignWithExactSigner(signer PersonalSigner, data string) ([]byte, error) {
	return signer.PersonalSign(data)
}

// PersonalSign flexibly signs data using the most appropriate method based on signer type
// It accepts any signer type and automatically chooses the best implementation:
// - If signer implements PersonalSigner, use PersonalSign directly
// - If signer implements EIP191Signer, use PersonalSignWithEIP191
// - If signer implements HashSigner, use PersonalSignWithHash
// This allows for maximum flexibility and automatic optimization
func PersonalSign(signer any, data string) ([]byte, error) {
	// Try PersonalSigner first (most specific)
	if ps, ok := signer.(PersonalSigner); ok {
		return ps.PersonalSign(data)
	}

	// Try EIP191Signer (uses EIP-191 message signing)
	if eip191, ok := signer.(EIP191Signer); ok {
		return PersonalSignWithEIP191(eip191, data)
	}

	// Try HashSigner (uses hash-based signing)
	if raw, ok := signer.(HashSigner); ok {
		return PersonalSignWithHash(raw, data)
	}

	return nil, fmt.Errorf("signer does not implement PersonalSigner, EIP191Signer, or HashSigner")
}

// PersonalSignWithHash implements personal_sign using a HashSigner (hash-based approach)
// This is a composable version that builds on top of SignHash
func PersonalSignWithHash(signer HashSigner, data string) ([]byte, error) {
	// Create the personal sign message format
	// "\x19Ethereum Signed Message:\n" + len(message) + message
	message := []byte(data)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message)))
	prefixedMessage := append(prefix, message...)

	// Hash the prefixed message
	hash := crypto.Keccak256Hash(prefixedMessage)

	// Sign using the HashSigner
	return signer.SignHash(hash)
}

// PersonalSignWithEIP191 implements personal_sign using an EIP191Signer
// This is a composable version that builds on top of SignEIP191Message
func PersonalSignWithEIP191(signer EIP191Signer, data string) ([]byte, error) {
	// Create the personal sign message format
	// "\x19Ethereum Signed Message:\n" + len(message) + message
	message := []byte(data)
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message)))
	prefixedMessage := append(prefix, message...)

	// Sign using EIP191Signer
	return signer.SignEIP191Message(string(prefixedMessage))
}

func SignRawMessageWithHashSigner(signer HashSigner, raw []byte) ([]byte, error) {
	digest := crypto.Keccak256Hash(raw)
	return signer.SignHash(digest)
}

// SignTypedDataWithExactSigner is a helper function that signs EIP-712 typed data
func SignTypedDataWithExactSigner(signer TypedDataSigner, typedData eip712.TypedData) ([]byte, error) {
	return signer.SignTypedData(typedData)
}

// SignTypedData flexibly signs EIP-712 typed data using the most appropriate method based on signer type
// It accepts any signer type and automatically chooses the best implementation:
// - If signer implements TypedDataSigner, use SignTypedData directly
// - If signer implements EIP191Signer, use SignTypedDataWithEIP191
// - If signer implements HashSigner, use SignTypedDataWithHash
// This allows for maximum flexibility and automatic optimization
func SignTypedData(signer any, typedData eip712.TypedData) ([]byte, error) {
	// Try TypedDataSigner first (most specific)
	if tds, ok := signer.(TypedDataSigner); ok {
		return tds.SignTypedData(typedData)
	}

	// Try EIP191Signer (uses EIP-191 message signing)
	if eip191, ok := signer.(EIP191Signer); ok {
		return SignTypedDataWithEIP191(eip191, typedData)
	}

	// Try HashSigner (uses hash-based signing)
	if raw, ok := signer.(HashSigner); ok {
		return SignTypedDataWithHash(raw, typedData)
	}

	return nil, fmt.Errorf("signer does not implement TypedDataSigner, EIP191Signer, or HashSigner")
}

// SignTypedDataWithHash implements EIP-712 signing using a HashSigner
// This is a composable version that builds on top of SignHash
func SignTypedDataWithHash(signer HashSigner, typedData eip712.TypedData) ([]byte, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash message: %w", err)
	}

	// Create EIP-191 version 0x01 message
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	digest := crypto.Keccak256Hash(rawData)

	signature, err := signer.SignHash(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// SignTypedDataWithEIP191 implements EIP-712 signing using an EIP191Signer
// This is a composable version that builds on top of SignEIP191Message
func SignTypedDataWithEIP191(signer EIP191Signer, typedData eip712.TypedData) ([]byte, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash message: %w", err)
	}

	// Create EIP-191 version 0x01 message
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))

	signature, err := signer.SignEIP191Message(string(rawData))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// SignTransactionWithExactSigner is a helper function that signs an Ethereum transaction
// It requires explicit chainID to ensure correct signing
func SignTransactionWithExactSigner(signer TransactionSigner, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return signer.SignTransactionWithChainID(tx, chainID)
}

// SignTransactionWithHashSigner implements transaction signing using a HashSigner
// This is a composable version that builds on top of SignHash
// It follows the same logic as types.SignTx but uses the HashSigner interface
// IMPORTANT: Always uses the provided chainID for signing, NOT tx.ChainId()
func SignTransactionWithHashSigner(signer HashSigner, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("transaction is nil")
	}

	if chainID == nil {
		return nil, fmt.Errorf("chainID is nil")
	}

	// Create a signer using LatestSignerForChainID which automatically selects
	// the appropriate signer based on transaction type (Legacy, EIP-2930, or EIP-1559)
	// IMPORTANT: Always use OUR chainID for signing, not tx.ChainId()
	// This is critical because:
	// 1. LegacyTx.ChainId() derives from V value, which might be MaxUint64 for unsigned tx
	// 2. We want to ensure we always sign with the correct chainID (e.g., 137 for Polygon)
	txSigner := types.LatestSignerForChainID(chainID)

	// Get the transaction hash that needs to be signed
	txHash := txSigner.Hash(tx)

	// Sign the hash using HashSigner
	signature, err := signer.SignHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction hash: %w", err)
	}

	// Adjust V value back to 0/1 for WithSignature (it expects 0/1, not 27/28)
	if len(signature) == 65 && signature[64] >= 27 {
		signature[64] -= 27
	}

	// Create signed transaction using the signature
	signedTx, err := tx.WithSignature(txSigner, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to apply signature to transaction: %w", err)
	}

	return signedTx, nil
}

// SignTransaction flexibly signs an Ethereum transaction using the most appropriate method based on signer type
// It accepts any signer type and automatically chooses the best implementation:
// - If signer implements TransactionSigner, use SignTransactionWithChainID directly
// - If signer implements HashSigner, use SignTransactionWithHashSigner
// This allows for maximum flexibility and automatic optimization
// IMPORTANT: Always provide explicit chainID to ensure correct signing
func SignTransaction(signer any, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Try TransactionSigner first (most specific)
	if ts, ok := signer.(TransactionSigner); ok {
		return ts.SignTransactionWithChainID(tx, chainID)
	}

	// Try HashSigner (uses hash-based signing)
	if raw, ok := signer.(HashSigner); ok {
		return SignTransactionWithHashSigner(raw, tx, chainID)
	}

	return nil, fmt.Errorf("signer does not implement TransactionSigner or HashSigner")
}

// NewBindSignerFn creates a bind.SignerFn from a TransactionSigner
// This function is used to convert our custom signer interface
// into the SignerFn type required by bind.TransactOpts
//
// Parameters:
//   - txSigner: The signer implementation (must implement both TransactionSigner/HashSigner and AddressGetter)
//   - chainID: The chain ID to use for signing (e.g., 137 for Polygon)
//
// # Returns a bind.SignerFn that can be assigned to bind.TransactOpts.Signer
//
// Example usage:
//
//	signerFn, err := signer.NewBindSignerFn(mySigner, big.NewInt(137))
//	if err != nil {
//	    return err
//	}
//	opts := &bind.TransactOpts{
//	    From: signer.GetAddress(mySigner),
//	    Signer: signerFn,
//	}
func NewBindSignerFn(txSigner any, chainID *big.Int) (bind.SignerFn, error) {
	if chainID == nil {
		return nil, fmt.Errorf("chainID is nil")
	}

	// Get the authorized address from the signer
	authorizedAddress, err := GetAddress(txSigner)
	if err != nil {
		return nil, fmt.Errorf("signer does not implement AddressGetter: %w", err)
	}

	return func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		// Verify the address matches the authorized address
		if address != authorizedAddress {
			return nil, fmt.Errorf("not authorized to sign for address %s (expected %s)", address.Hex(), authorizedAddress.Hex())
		}

		// Use SignTransaction to handle both TransactionSigner and HashSigner
		return SignTransaction(txSigner, tx, chainID)
	}, nil
}

// GetAddressWithExactGetter is a helper function that returns the address associated with an AddressGetter
func GetAddressWithExactGetter(getter AddressGetter) common.Address {
	return getter.GetAddress()
}

// GetAddress flexibly returns the address associated with a signer
// It accepts any signer type and automatically chooses the best implementation:
// - If signer implements AddressGetter, use GetAddress directly
// This allows for maximum flexibility and future extensibility
func GetAddress(signer any) (common.Address, error) {
	// Try AddressGetter
	if ag, ok := signer.(AddressGetter); ok {
		return ag.GetAddress(), nil
	}

	return common.Address{}, fmt.Errorf("signer does not implement AddressGetter")
}
