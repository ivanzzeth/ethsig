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
			return NewValidationError("invalid EIP-191 version 0x00 message", fmt.Errorf("minimum length is 22 bytes, got %d", len(message)))
		}
		return nil

	case 0x01: // Structured data (EIP-712)
		// Format: 0x19 <0x01> <domainSeparator (32 bytes)> <hashStruct (32 bytes)>
		// Total length: 1 + 1 + 32 + 32 = 66 bytes
		if len(message) != 66 {
			return NewValidationError("invalid EIP-191 version 0x01 (EIP-712) message", fmt.Errorf("expected 66 bytes, got %d", len(message)))
		}
		return nil

	case 0x45: // personal_sign messages (Ethereum Signed Message)
		// Format: 0x19 <0x45 ('E')> <"thereum Signed Message:\n" + len(message)> <message>
		// Full format: \x19Ethereum Signed Message:\n{len}{message}
		expectedPrefix := []byte("\x19Ethereum Signed Message:\n")
		if !bytes.HasPrefix(message, expectedPrefix) {
			return NewValidationError("invalid EIP-191 version 0x45 message", fmt.Errorf("missing 'Ethereum Signed Message:' prefix"))
		}

		// Extract the length part after the prefix
		lengthPart := message[len(expectedPrefix):]

		// Find where the actual message starts (after the length digits)
		// The length is a decimal number followed immediately by the message
		lengthEndPos := 0
		for lengthEndPos < len(lengthPart) && lengthPart[lengthEndPos] >= '0' && lengthPart[lengthEndPos] <= '9' {
			lengthEndPos++
		}

		if lengthEndPos == 0 {
			return NewValidationError("invalid EIP-191 version 0x45 message", fmt.Errorf("no length found"))
		}

		// Parse the length
		lengthStr := string(lengthPart[:lengthEndPos])
		expectedLength, err := strconv.Atoi(lengthStr)
		if err != nil {
			return NewValidationError("invalid EIP-191 version 0x45 message", fmt.Errorf("invalid length format: %w", err))
		}

		// Calculate where the message should start
		messageStart := len(expectedPrefix) + lengthEndPos

		// Verify the actual message length matches the declared length
		actualLength := len(message) - messageStart
		if actualLength != expectedLength {
			return NewValidationError("invalid EIP-191 version 0x45 message", fmt.Errorf("declared length %d, actual length %d", expectedLength, actualLength))
		}

		return nil

	default:
		return NewValidationError("unsupported EIP-191 version byte", fmt.Errorf("0x%02x", message[1]))
	}
}

// ValidateSignatureLength validates that a signature has the correct length
func ValidateSignatureLength(signature []byte) error {
	if len(signature) != 65 {
		return NewValidationError("invalid signature length", fmt.Errorf("expected 65 bytes, got %d", len(signature)))
	}
	return nil
}

// ValidateAddress validates that an address is a valid Ethereum address
func ValidateAddress(address common.Address) error {
	if address == (common.Address{}) {
		return NewValidationError("address is zero address", nil)
	}
	
	if !common.IsHexAddress(address.Hex()) {
		return NewValidationError("invalid Ethereum address format", fmt.Errorf("%s", address.Hex()))
	}
	
	return nil
}

// ValidateChainID validates that a chain ID is valid
func ValidateChainID(chainID *big.Int) error {
	if chainID == nil {
		return NewValidationError("chainID is nil", nil)
	}
	
	if chainID.Sign() <= 0 {
		return NewValidationError("chainID must be positive", nil)
	}
	
	return nil
}
