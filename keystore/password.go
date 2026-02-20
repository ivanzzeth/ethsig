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

// ReadSecret reads a secret from stdin without echoing, with context support.
// Returns error if stdin is not a terminal to prevent insecure piping.
// If context is canceled, it restores terminal state, unblocks the internal
// ReadPassword goroutine, and waits for it to exit before returning.
func ReadSecret(ctx context.Context) ([]byte, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return nil, ErrNotTerminal
	}

	// Save terminal state before reading password.
	// term.ReadPassword puts the terminal into raw mode; we must be able
	// to restore no matter how we exit.
	oldState, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to get terminal state: %w", err)
	}

	type result struct {
		password []byte
		err      error
	}
	resultCh := make(chan result, 1)

	go func() {
		password, err := term.ReadPassword(fd)
		resultCh <- result{password: password, err: err}
	}()

	select {
	case <-ctx.Done():
		// Context canceled while ReadPassword is blocking in raw mode.
		// Steps to clean up safely:
		//  1. Restore terminal state (exits raw mode so the read unblocks or
		//     at least stops altering the terminal after we return).
		//  2. Write a newline to stdin to unblock the blocked read syscall
		//     inside term.ReadPassword, so the goroutine can finish.
		//  3. Wait for the goroutine to send its result, preventing a leak.
		_ = term.Restore(fd, oldState)
		_, _ = syscall.Write(fd, []byte("\n"))
		<-resultCh
		return nil, fmt.Errorf("%w: %v", ErrContextCanceled, ctx.Err())

	case res := <-resultCh:
		// ReadPassword completed (user pressed Enter or an error occurred).
		// Restore terminal state in case ReadPassword left it modified.
		_ = term.Restore(fd, oldState)
		if res.err != nil {
			return nil, fmt.Errorf("failed to read password: %w", res.err)
		}
		fmt.Println() // newline after password input
		return res.password, nil
	}
}

// ReadPasswordWithConfirm reads a password twice for confirmation.
// Returns error if passwords don't match or if stdin is not a terminal.
func ReadPasswordWithConfirm(ctx context.Context, prompt string) ([]byte, error) {
	fmt.Printf("%s: ", prompt)
	password1, err := ReadSecret(ctx)
	if err != nil {
		return nil, err
	}

	if len(password1) == 0 {
		return nil, ErrEmptyPassword
	}

	fmt.Print("Confirm password: ")
	password2, err := ReadSecret(ctx)
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
