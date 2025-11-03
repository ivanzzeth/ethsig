package ethsig

import (
	"bytes"
	"fmt"
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
		// The message must contain at least the prefix plus length indicator
		if len(message) <= len(expectedPrefix) {
			return fmt.Errorf("invalid EIP-191 version 0x45 message: no message length found")
		}
		return nil

	default:
		return fmt.Errorf("unsupported EIP-191 version byte: 0x%02x", message[1])
	}
}
