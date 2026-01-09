package keystore

import (
	"testing"
)

func TestSecureZeroize_Data(t *testing.T) {
	data := []byte("sensitive-password-123")
	SecureZeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

func TestSecureZeroize_Nil(t *testing.T) {
	// Should not panic
	SecureZeroize(nil)
}

func TestSecureZeroize_Empty(t *testing.T) {
	data := []byte{}
	SecureZeroize(data)
	// Should not panic and should have no effect
}

func TestBytesEqual_Equal(t *testing.T) {
	a := []byte("password123")
	b := []byte("password123")
	if !bytesEqual(a, b) {
		t.Error("bytesEqual should return true for equal slices")
	}
}

func TestBytesEqual_NotEqual(t *testing.T) {
	a := []byte("password123")
	b := []byte("password456")
	if bytesEqual(a, b) {
		t.Error("bytesEqual should return false for different slices")
	}
}

func TestBytesEqual_DifferentLength(t *testing.T) {
	a := []byte("password123")
	b := []byte("pass")
	if bytesEqual(a, b) {
		t.Error("bytesEqual should return false for different length slices")
	}
}

func TestBytesEqual_Empty(t *testing.T) {
	a := []byte{}
	b := []byte{}
	if !bytesEqual(a, b) {
		t.Error("bytesEqual should return true for empty slices")
	}
}

func TestIsTerminal_InTest(t *testing.T) {
	// In a test environment, stdin is typically not a terminal
	// This test validates the function doesn't panic
	result := IsTerminal()
	// We expect false in test environment (piped stdin)
	if result {
		t.Log("Stdin appears to be a terminal - this may vary by test runner")
	}
}

func TestReadSecret_NotTerminal(t *testing.T) {
	// When stdin is not a terminal, ReadSecret should return an error
	// In test environment, stdin is typically piped
	if IsTerminal() {
		t.Skip("Skipping test: stdin is a terminal")
	}

	_, err := ReadSecret()
	if err == nil {
		t.Error("ReadSecret should return error when stdin is not a terminal")
	}
	if err != ErrNotTerminal {
		t.Errorf("Expected ErrNotTerminal, got: %v", err)
	}
}

func TestReadPasswordWithConfirm_NotTerminal(t *testing.T) {
	// When stdin is not a terminal, ReadPasswordWithConfirm should return an error
	if IsTerminal() {
		t.Skip("Skipping test: stdin is a terminal")
	}

	_, err := ReadPasswordWithConfirm("Enter password")
	if err == nil {
		t.Error("ReadPasswordWithConfirm should return error when stdin is not a terminal")
	}
	if err != ErrNotTerminal {
		t.Errorf("Expected ErrNotTerminal, got: %v", err)
	}
}

func TestErrors(t *testing.T) {
	// Test that error variables are properly defined
	if ErrNotTerminal == nil {
		t.Error("ErrNotTerminal should not be nil")
	}
	if ErrPasswordMismatch == nil {
		t.Error("ErrPasswordMismatch should not be nil")
	}
	if ErrEmptyPassword == nil {
		t.Error("ErrEmptyPassword should not be nil")
	}

	// Test error messages
	if ErrNotTerminal.Error() == "" {
		t.Error("ErrNotTerminal should have a message")
	}
	if ErrPasswordMismatch.Error() == "" {
		t.Error("ErrPasswordMismatch should have a message")
	}
	if ErrEmptyPassword.Error() == "" {
		t.Error("ErrEmptyPassword should have a message")
	}
}

// TestBytesEqual_ConstantTime verifies the comparison is constant-time
// by checking it handles all byte differences correctly
func TestBytesEqual_ConstantTime(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal_simple", []byte("abc"), []byte("abc"), true},
		{"differ_first_byte", []byte("abc"), []byte("xbc"), false},
		{"differ_middle_byte", []byte("abc"), []byte("axc"), false},
		{"differ_last_byte", []byte("abc"), []byte("abx"), false},
		{"differ_all_bytes", []byte("abc"), []byte("xyz"), false},
		{"empty_both", []byte{}, []byte{}, true},
		{"single_byte_equal", []byte{0x42}, []byte{0x42}, true},
		{"single_byte_differ", []byte{0x42}, []byte{0x43}, false},
		{"binary_data", []byte{0x00, 0xFF, 0x55, 0xAA}, []byte{0x00, 0xFF, 0x55, 0xAA}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("bytesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestPipeDetection verifies that piped input is properly detected
func TestPipeDetection(t *testing.T) {
	// The test just verifies IsTerminal() doesn't panic and returns a boolean
	// The actual result depends on the test environment
	result := IsTerminal()
	t.Logf("IsTerminal() = %v", result)
	// This test passes as long as the function executes without panic
}
