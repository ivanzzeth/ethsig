//go:build windows

package keystore

import "syscall"

// writeStdin is the Windows counterpart of the Unix helper. syscall.Write
// on Windows takes a syscall.Handle (a uintptr alias) rather than an int
// file descriptor, so we cast before calling.
//
// Note: writing to the same console handle a goroutine is reading from
// behaves differently on Windows than on Unix TTYs and may not unblock
// term.ReadPassword in every scenario. The caller treats cancellation as
// best-effort, so a goroutine that doesn't release here will be torn down
// when the process exits. Cross-platform behaviour is documented in
// password.go's ReadSecret.
func writeStdin(fd int, p []byte) error {
	_, err := syscall.Write(syscall.Handle(fd), p)
	return err
}
