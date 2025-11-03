package ethsig

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// RSV represents the R, S, V components of an Ethereum signature
type RSV struct {
	R [32]byte // R component
	S [32]byte // S component
	V uint8    // V component (recovery ID)
}

// ConvertSigBytes2RSV converts a signature byte slice to R, S, V components
// Input: 65-byte signature (R: 32 bytes, S: 32 bytes, V: 1 byte)
// Output: R, S, V components
//
// Example:
// Input:  0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c
// Output:
//
//	R: 0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f
//	S: 0x797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244
//	V: 28
func ConvertSigBytes2RSV(sig []byte) (r [32]byte, s [32]byte, v uint8, err error) {
	if len(sig) != 65 {
		err = fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(sig))
		return
	}

	// Extract R (first 32 bytes)
	copy(r[:], sig[0:32])

	// Extract S (next 32 bytes)
	copy(s[:], sig[32:64])

	// Extract V (last byte)
	v = sig[64]

	// Normalize V to 27 or 28 if needed (some implementations use 0/1)
	if v < 27 {
		v += 27
	}

	return
}

// ConvertSigHex2RSV converts a hex-encoded signature string to R, S, V components
// The hex string should be 130 characters (65 bytes * 2) with optional "0x" prefix
//
// Example:
// Input:  "0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
// Output:
//
//	R: 0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f
//	S: 0x797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244
//	V: 28
func ConvertSigHex2RSV(sigHex string) (r [32]byte, s [32]byte, v uint8, err error) {
	// Remove "0x" prefix if present
	if len(sigHex) >= 2 && sigHex[0:2] == "0x" {
		sigHex = sigHex[2:]
	}

	// Decode hex string to bytes
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		err = fmt.Errorf("failed to decode hex signature: %w", err)
		return
	}

	return ConvertSigBytes2RSV(sig)
}

// ConvertRSV2SigBytes converts R, S, V components to a signature byte slice
// This is the reverse operation of ConvertSigBytes2RSV
//
// Example:
// Input:
//
//	R: 0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f
//	S: 0x797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244
//	V: 28
//
// Output: 0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c
func ConvertRSV2SigBytes(r [32]byte, s [32]byte, v uint8) []byte {
	sig := make([]byte, 65)
	copy(sig[0:32], r[:])
	copy(sig[32:64], s[:])
	sig[64] = v
	return sig
}

// ConvertRSV2SigHex converts R, S, V components to a hex-encoded signature string with "0x" prefix
//
// Example:
// Input:
//
//	R: 0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f
//	S: 0x797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244
//	V: 28
//
// Output: "0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
func ConvertRSV2SigHex(r [32]byte, s [32]byte, v uint8) string {
	sig := ConvertRSV2SigBytes(r, s, v)
	return "0x" + hex.EncodeToString(sig)
}

// NormalizeV normalizes the V value to the standard format (27 or 28)
// Some implementations use 0/1, this converts them to 27/28
func NormalizeV(v uint8) uint8 {
	if v < 27 {
		return v + 27
	}
	return v
}

// DenormalizeV converts V from 27/28 to 0/1 format
// This is useful for some contract interactions that expect 0/1
func DenormalizeV(v uint8) uint8 {
	if v >= 27 {
		return v - 27
	}
	return v
}

// RSVToStruct converts R, S, V byte arrays to an RSV struct
func RSVToStruct(r [32]byte, s [32]byte, v uint8) RSV {
	return RSV{
		R: r,
		S: s,
		V: v,
	}
}

// StructToRSV extracts R, S, V from an RSV struct
func StructToRSV(rsv RSV) (r [32]byte, s [32]byte, v uint8) {
	return rsv.R, rsv.S, rsv.V
}

// ParseSignatureComponents parses a signature into its components and returns them as big.Int and uint8
// This is useful for contract interactions that require *big.Int types
func ParseSignatureComponents(sig []byte) (r *big.Int, s *big.Int, v uint8, err error) {
	rBytes, sBytes, vVal, err := ConvertSigBytes2RSV(sig)
	if err != nil {
		return nil, nil, 0, err
	}

	r = new(big.Int).SetBytes(rBytes[:])
	s = new(big.Int).SetBytes(sBytes[:])
	v = vVal

	return r, s, v, nil
}

// FormatSignatureHex formats R, S, V components as a pretty-printed string
func FormatSignatureHex(r [32]byte, s [32]byte, v uint8) string {
	return fmt.Sprintf("(r: 0x%x\ns: 0x%x\nv: %d)", r, s, v)
}

func ValidateSignature(signer common.Address, hashedData common.Hash, signature []byte) (bool, error) {
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	if len(sigCopy) != 65 {
		return false, ErrInvalidSignatureLen
	}

	if sigCopy[64] != 0 && sigCopy[64] != 1 { // in case of ledger signing v might already be 0 or 1
		sigCopy[64] -= 27 // Transform V from 27/28 to 0/1 according to the yellow paper
	}

	sigPublicKey, err := crypto.Ecrecover(hashedData.Bytes(), sigCopy)
	if err != nil {
		return false, err
	}

	recoveredPublicKey, err := crypto.UnmarshalPubkey(sigPublicKey)
	if err != nil {
		return false, err
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPublicKey)
	return bytes.Equal(signer.Bytes(), recoveredAddress.Bytes()), nil
}
