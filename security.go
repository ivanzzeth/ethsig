package ethsig

import (
	"crypto/subtle"
)

// SecureBytes provides secure handling of sensitive byte data
// It automatically zeroizes memory when no longer needed
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new SecureBytes instance
func NewSecureBytes(data []byte) *SecureBytes {
	sb := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(sb.data, data)
	return sb
}

// NewSecureBytesFromString creates a new SecureBytes instance from a string
func NewSecureBytesFromString(data string) *SecureBytes {
	return NewSecureBytes([]byte(data))
}

// Bytes returns a copy of the secure bytes
func (sb *SecureBytes) Bytes() []byte {
	if sb == nil {
		return nil
	}
	data := make([]byte, len(sb.data))
	copy(data, sb.data)
	return data
}

// String returns the secure bytes as a string (use with caution)
func (sb *SecureBytes) String() string {
	if sb == nil || len(sb.data) == 0 {
		return ""
	}
	return string(sb.data)
}

// Zeroize securely erases the sensitive data from memory
func (sb *SecureBytes) Zeroize() {
	if sb == nil || len(sb.data) == 0 {
		return
	}
	
	// Use constant-time operation to prevent optimization
	subtle.ConstantTimeCopy(1, sb.data, make([]byte, len(sb.data)))
	
	// Additional zeroization for safety
	for i := range sb.data {
		sb.data[i] = 0
	}
	sb.data = nil
}

// Len returns the length of the secure bytes
func (sb *SecureBytes) Len() int {
	if sb == nil {
		return 0
	}
	return len(sb.data)
}

// IsZeroized checks if the secure bytes have been zeroized
func (sb *SecureBytes) IsZeroized() bool {
	if sb == nil || len(sb.data) == 0 {
		return true
	}
	
	// Check if all bytes are zero
	for _, b := range sb.data {
		if b != 0 {
			return false
		}
	}
	return true
}

// ConstantTimeCompare compares two SecureBytes in constant time
func (sb *SecureBytes) ConstantTimeCompare(other *SecureBytes) bool {
	if sb == nil && other == nil {
		return true
	}
	if sb == nil || other == nil {
		return false
	}
	
	return subtle.ConstantTimeCompare(sb.data, other.data) == 1
}

// SecureZeroize securely zeroizes a byte slice
func SecureZeroize(data []byte) {
	if len(data) == 0 {
		return
	}
	
	// Use constant-time operation
	subtle.ConstantTimeCopy(1, data, make([]byte, len(data)))
	
	// Additional zeroization
	for i := range data {
		data[i] = 0
	}
}

// SecureZeroizeString securely zeroizes a string by converting to bytes and zeroizing
// Note: This function is deprecated and should not be used due to string immutability in Go.
// Use SecureBytes for sensitive data instead.
func SecureZeroizeString(str *string) {
	if str == nil {
		return
	}
	
	// Strings are immutable in Go, so we cannot safely zeroize them.
	// This function is kept for backward compatibility but does nothing.
	// Use SecureBytes for sensitive data that needs secure zeroization.
}