package keystore

import (
	"context"
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

	// ErrContextCanceled is returned when context is canceled during password reading
	ErrContextCanceled = errors.New("password reading canceled by context")
)

// ReadSecret reads a secret from stdin without echoing.
// Returns error if stdin is not a terminal to prevent insecure piping.
func ReadSecret() ([]byte, error) {
	return ReadSecretWithContext(context.Background())
}

// ReadSecretWithContext reads a secret from stdin without echoing, with context support.
// Returns error if stdin is not a terminal to prevent insecure piping.
// If context is canceled, returns ErrContextCanceled.
func ReadSecretWithContext(ctx context.Context) ([]byte, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return nil, ErrNotTerminal
	}

	// Save terminal state before reading password
	// term.ReadPassword will modify terminal state, so we need to restore it
	// if context is canceled before ReadPassword completes
	oldState, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to get terminal state: %w", err)
	}

	// Ensure terminal state is always restored on exit
	// This is critical: if context is canceled, we must restore terminal state immediately
	// without waiting for ReadPassword to complete (which may never happen)
	defer func() {
		if restoreErr := term.Restore(fd, oldState); restoreErr != nil {
			// Log but don't fail - terminal might already be restored
			_ = restoreErr
		}
	}()

	// Use a channel to communicate between goroutines
	type result struct {
		password []byte
		err      error
	}
	resultCh := make(chan result, 1)

	// Read password in a goroutine so we can cancel it
	go func() {
		password, err := term.ReadPassword(fd)
		resultCh <- result{password: password, err: err}
	}()

	// Wait for either context cancellation or password reading completion
	select {
	case <-ctx.Done():
		// Context was canceled - immediately restore terminal state and return
		// We don't wait for ReadPassword to complete because:
		// 1. It may never complete (user pressed Ctrl+C, it's still waiting for input)
		// 2. The defer will restore terminal state immediately when we return
		// 3. The goroutine will continue running but its result will be discarded
		return nil, fmt.Errorf("%w: %v", ErrContextCanceled, ctx.Err())
	case res := <-resultCh:
		// ReadPassword completed normally
		// Terminal state will be restored by defer (though ReadPassword may have already restored it)
		if res.err != nil {
			return nil, fmt.Errorf("failed to read password: %w", res.err)
		}
		fmt.Println() // newline after password input
		return res.password, nil
	}
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
