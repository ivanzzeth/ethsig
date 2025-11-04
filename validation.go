package ethsig

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

func ValidateEIP191Message(message []byte) error {
	// EIP-191 messages must start with 0x19
	if len(message) < 2 {
		return ErrInvalidEIP191MessagePrefix
	}

	if !bytes.HasPrefix(message, []byte{0x19}) {
		return ErrInvalidEIP191MessagePrefix
	}

	switch message[1] {
	case 0x00: // Data with intended validator
		// Format: 0x19 <0x00> <intended validator address (20 bytes)> <data to sign>
		// Minimum length: 1 + 1 + 20 = 22 bytes
		if len(message) < 22 {
			return fmt.Errorf("invalid EIP-191 version 0x00 message: minimum length is 22 bytes, got %d", len(message))
		}
		return nil

	case 0x01: // Structured data (EIP-712)
		// Format: 0x19 <0x01> <domainSeparator (32 bytes)> <hashStruct (32 bytes)>
		// Total length: 1 + 1 + 32 + 32 = 66 bytes
		if len(message) != 66 {
			return fmt.Errorf("invalid EIP-191 version 0x01 (EIP-712) message: expected 66 bytes, got %d", len(message))
		}
		return nil

	case 0x45: // personal_sign messages (Ethereum Signed Message)
		// Format: 0x19 <0x45 ('E')> <"thereum Signed Message:\n" + len(message)> <message>
		expectedPrefix := []byte("\x19Ethereum Signed Message:\n")
		if !bytes.HasPrefix(message, expectedPrefix) {
			return fmt.Errorf("invalid EIP-191 version 0x45 message: missing 'Ethereum Signed Message:' prefix")
		}
		
		// Extract the length part after the prefix
		lengthPart := message[len(expectedPrefix):]
		
		// Find the newline that separates length from message
		newlinePos := bytes.IndexByte(lengthPart, '\n')
		if newlinePos == -1 {
			return fmt.Errorf("invalid EIP-191 version 0x45 message: no newline found after length")
		}
		
		// Parse the length
		lengthStr := string(lengthPart[:newlinePos])
		expectedLength, err := strconv.Atoi(lengthStr)
		if err != nil {
			return fmt.Errorf("invalid EIP-191 version 0x45 message: invalid length format: %w", err)
		}
		
		// Calculate where the message should start
		messageStart := len(expectedPrefix) + newlinePos + 1
		
		// Verify the actual message length matches the declared length
		actualLength := len(message) - messageStart
		if actualLength != expectedLength {
			return fmt.Errorf("invalid EIP-191 version 0x45 message: declared length %d, actual length %d", expectedLength, actualLength)
		}
		
		return nil

	default:
		return fmt.Errorf("unsupported EIP-191 version byte: 0x%02x", message[1])
	}
}

// ValidateSignatureLength validates that a signature has the correct length
func ValidateSignatureLength(signature []byte) error {
	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(signature))
	}
	return nil
}

// ValidateAddress validates that an address is a valid Ethereum address
func ValidateAddress(address common.Address) error {
	if address == (common.Address{}) {
		return fmt.Errorf("address is zero address")
	}
	
	if !common.IsHexAddress(address.Hex()) {
		return fmt.Errorf("invalid Ethereum address format: %s", address.Hex())
	}
	
	return nil
}

// ValidateChainID validates that a chain ID is valid
func ValidateChainID(chainID *big.Int) error {
	if chainID == nil {
		return fmt.Errorf("chainID is nil")
	}
	
	if chainID.Sign() <= 0 {
		return fmt.Errorf("chainID must be positive")
	}
	
	return nil
}
