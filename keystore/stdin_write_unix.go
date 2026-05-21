//go:build !windows

package keystore

import "syscall"

// writeStdin pushes p back into stdin to unblock a goroutine that is
// currently inside term.ReadPassword on the same fd. On Unix syscall.Write
// takes an int file descriptor, matching the one we already track in the
// caller.
func writeStdin(fd int, p []byte) error {
	_, err := syscall.Write(fd, p)
	return err
}
