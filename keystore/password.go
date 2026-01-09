package keystore

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/term"
)

var (
	// ErrNotTerminal is returned when stdin is not a terminal
	ErrNotTerminal = errors.New("stdin is not a terminal, cannot read password securely")

	// ErrPasswordMismatch is returned when password confirmation does not match
	ErrPasswordMismatch = errors.New("passwords do not match")

	// ErrEmptyPassword is returned when password is empty
	ErrEmptyPassword = errors.New("password cannot be empty")
)

// ReadSecret reads a secret from stdin without echoing.
// Returns error if stdin is not a terminal to prevent insecure piping.
func ReadSecret() ([]byte, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return nil, ErrNotTerminal
	}

	password, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // newline after password input

	return password, nil
}

// ReadPasswordWithConfirm reads a password twice for confirmation.
// Returns error if passwords don't match or if stdin is not a terminal.
func ReadPasswordWithConfirm(prompt string) ([]byte, error) {
	fmt.Printf("%s: ", prompt)
	password1, err := ReadSecret()
	if err != nil {
		return nil, err
	}

	if len(password1) == 0 {
		return nil, ErrEmptyPassword
	}

	fmt.Print("Confirm password: ")
	password2, err := ReadSecret()
	if err != nil {
		SecureZeroize(password1)
		return nil, err
	}

	if !bytesEqual(password1, password2) {
		SecureZeroize(password1)
		SecureZeroize(password2)
		return nil, ErrPasswordMismatch
	}

	SecureZeroize(password2)
	return password1, nil
}

// SecureZeroize securely erases sensitive data from memory.
// This function should be called with defer after reading a password.
func SecureZeroize(data []byte) {
	if data == nil {
		return
	}
	for i := range data {
		data[i] = 0
	}
}

// bytesEqual compares two byte slices in constant time to prevent timing attacks.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// IsTerminal checks if stdin is a terminal.
func IsTerminal() bool {
	fd := int(syscall.Stdin)
	return term.IsTerminal(fd)
}
