package ethsig

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestConvertSigBytes2RSV(t *testing.T) {
	// Test signature from the example
	sigHex := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	r, s, v, err := ConvertSigBytes2RSV(sig)
	if err != nil {
		t.Fatalf("ConvertSigBytes2RSV failed: %v", err)
	}

	// Verify R
	expectedR := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f"
	actualR := hex.EncodeToString(r[:])
	if actualR != expectedR {
		t.Errorf("R mismatch:\nExpected: %s\nGot:      %s", expectedR, actualR)
	}

	// Verify S
	expectedS := "797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244"
	actualS := hex.EncodeToString(s[:])
	if actualS != expectedS {
		t.Errorf("S mismatch:\nExpected: %s\nGot:      %s", expectedS, actualS)
	}

	// Verify V
	expectedV := uint8(28)
	if v != expectedV {
		t.Errorf("V mismatch:\nExpected: %d\nGot:      %d", expectedV, v)
	}
}

func TestConvertSigHex2RSV(t *testing.T) {
	// Test with 0x prefix
	sigHex := "0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"

	r, s, v, err := ConvertSigHex2RSV(sigHex)
	if err != nil {
		t.Fatalf("ConvertSigHex2RSV failed: %v", err)
	}

	// Verify R
	expectedR := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f"
	actualR := hex.EncodeToString(r[:])
	if actualR != expectedR {
		t.Errorf("R mismatch:\nExpected: %s\nGot:      %s", expectedR, actualR)
	}

	// Verify S
	expectedS := "797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244"
	actualS := hex.EncodeToString(s[:])
	if actualS != expectedS {
		t.Errorf("S mismatch:\nExpected: %s\nGot:      %s", expectedS, actualS)
	}

	// Verify V (1c in hex = 28 in decimal)
	expectedV := uint8(28)
	if v != expectedV {
		t.Errorf("V mismatch:\nExpected: %d\nGot:      %d", expectedV, v)
	}
}

func TestConvertRSV2SigBytes(t *testing.T) {
	// Create R, S, V components
	rHex := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f"
	sHex := "797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244"

	var r, s [32]byte
	rBytes, _ := hex.DecodeString(rHex)
	sBytes, _ := hex.DecodeString(sHex)
	copy(r[:], rBytes)
	copy(s[:], sBytes)
	v := uint8(28)

	// Convert back to signature bytes
	sig := ConvertRSV2SigBytes(r, s, v)

	// Verify length
	if len(sig) != 65 {
		t.Errorf("Signature length mismatch: expected 65, got %d", len(sig))
	}

	// Verify the signature matches the original
	expectedSig := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
	actualSig := hex.EncodeToString(sig)
	if actualSig != expectedSig {
		t.Errorf("Signature mismatch:\nExpected: %s\nGot:      %s", expectedSig, actualSig)
	}
}

func TestConvertRSV2SigHex(t *testing.T) {
	// Create R, S, V components
	rHex := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f"
	sHex := "797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244"

	var r, s [32]byte
	rBytes, _ := hex.DecodeString(rHex)
	sBytes, _ := hex.DecodeString(sHex)
	copy(r[:], rBytes)
	copy(s[:], sBytes)
	v := uint8(28)

	// Convert to hex string
	sigHex := ConvertRSV2SigHex(r, s, v)

	// Verify the result
	expectedSigHex := "0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
	if sigHex != expectedSigHex {
		t.Errorf("Signature hex mismatch:\nExpected: %s\nGot:      %s", expectedSigHex, sigHex)
	}
}

func TestNormalizeV(t *testing.T) {
	tests := []struct {
		input    uint8
		expected uint8
	}{
		{0, 27},
		{1, 28},
		{27, 27},
		{28, 28},
	}

	for _, tt := range tests {
		result := NormalizeV(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeV(%d) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

func TestDenormalizeV(t *testing.T) {
	tests := []struct {
		input    uint8
		expected uint8
	}{
		{27, 0},
		{28, 1},
		{0, 0},
		{1, 1},
	}

	for _, tt := range tests {
		result := DenormalizeV(tt.input)
		if result != tt.expected {
			t.Errorf("DenormalizeV(%d) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

func TestParseSignatureComponents(t *testing.T) {
	sigHex := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"
	sig, _ := hex.DecodeString(sigHex)

	r, s, v, err := ParseSignatureComponents(sig)
	if err != nil {
		t.Fatalf("ParseSignatureComponents failed: %v", err)
	}

	// Verify R
	expectedR := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f"
	expectedRBig := new(big.Int)
	expectedRBig.SetString(expectedR, 16)
	if r.Cmp(expectedRBig) != 0 {
		t.Errorf("R mismatch:\nExpected: %s\nGot:      %s", expectedRBig.Text(16), r.Text(16))
	}

	// Verify S
	expectedS := "797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244"
	expectedSBig := new(big.Int)
	expectedSBig.SetString(expectedS, 16)
	if s.Cmp(expectedSBig) != 0 {
		t.Errorf("S mismatch:\nExpected: %s\nGot:      %s", expectedSBig.Text(16), s.Text(16))
	}

	// Verify V
	expectedV := uint8(28)
	if v != expectedV {
		t.Errorf("V mismatch:\nExpected: %d\nGot:      %d", expectedV, v)
	}
}

func TestRoundTrip(t *testing.T) {
	// Original signature
	originalSigHex := "0x4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f2441c"

	// Convert to RSV
	r, s, v, err := ConvertSigHex2RSV(originalSigHex)
	if err != nil {
		t.Fatalf("Failed to convert to RSV: %v", err)
	}

	// Convert back to hex
	reconstructedSigHex := ConvertRSV2SigHex(r, s, v)

	// Verify they match
	if originalSigHex != reconstructedSigHex {
		t.Errorf("Round trip failed:\nOriginal:      %s\nReconstructed: %s", originalSigHex, reconstructedSigHex)
	}
}

func TestInvalidSignatureLength(t *testing.T) {
	// Test with invalid signature length
	invalidSig := make([]byte, 64) // Should be 65 bytes

	_, _, _, err := ConvertSigBytes2RSV(invalidSig)
	if err == nil {
		t.Error("Expected error for invalid signature length, got nil")
	}
}

func TestNormalizeRecoveryID(t *testing.T) {
	tests := []struct {
		name     string
		v        *big.Int
		chainID  *big.Int
		expected byte
		wantErr  bool
	}{
		// Modern tx types (EIP-1559, EIP-2930): V = 0 or 1
		{name: "modern V=0", v: big.NewInt(0), chainID: nil, expected: 0},
		{name: "modern V=1", v: big.NewInt(1), chainID: nil, expected: 1},
		{name: "modern V=0 with chainID", v: big.NewInt(0), chainID: big.NewInt(1), expected: 0},
		{name: "modern V=1 with chainID", v: big.NewInt(1), chainID: big.NewInt(137), expected: 1},

		// Legacy pre-EIP-155: V = 27 or 28
		{name: "pre-EIP-155 V=27", v: big.NewInt(27), chainID: nil, expected: 0},
		{name: "pre-EIP-155 V=28", v: big.NewInt(28), chainID: nil, expected: 1},
		{name: "pre-EIP-155 V=27 with chainID", v: big.NewInt(27), chainID: big.NewInt(1), expected: 0},
		{name: "pre-EIP-155 V=28 with chainID", v: big.NewInt(28), chainID: big.NewInt(1), expected: 1},

		// Legacy EIP-155 with chainID=1: V = recovery_id + 35 + 1*2 = recovery_id + 37
		{name: "EIP-155 chainID=1 V=37 (recovery=0)", v: big.NewInt(37), chainID: big.NewInt(1), expected: 0},
		{name: "EIP-155 chainID=1 V=38 (recovery=1)", v: big.NewInt(38), chainID: big.NewInt(1), expected: 1},

		// Legacy EIP-155 with chainID=137: V = recovery_id + 35 + 137*2 = recovery_id + 309
		{name: "EIP-155 chainID=137 V=309 (recovery=0)", v: big.NewInt(309), chainID: big.NewInt(137), expected: 0},
		{name: "EIP-155 chainID=137 V=310 (recovery=1)", v: big.NewInt(310), chainID: big.NewInt(137), expected: 1},

		// Legacy EIP-155 with chainID=56 (BSC): V = recovery_id + 35 + 56*2 = recovery_id + 147
		{name: "EIP-155 chainID=56 V=147 (recovery=0)", v: big.NewInt(147), chainID: big.NewInt(56), expected: 0},
		{name: "EIP-155 chainID=56 V=148 (recovery=1)", v: big.NewInt(148), chainID: big.NewInt(56), expected: 1},

		// Error cases
		{name: "nil V", v: nil, chainID: nil, expected: 0, wantErr: true},
		{name: "invalid V without chainID", v: big.NewInt(37), chainID: nil, expected: 0, wantErr: true},
		{name: "invalid V=99 with chainID=1", v: big.NewInt(99), chainID: big.NewInt(1), expected: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeRecoveryID(tt.v, tt.chainID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NormalizeRecoveryID() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeRecoveryID() unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("NormalizeRecoveryID() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestEncodeSignature(t *testing.T) {
	r := new(big.Int)
	r.SetString("4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f", 16)
	s := new(big.Int)
	s.SetString("797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f244", 16)

	tests := []struct {
		name       string
		r          *big.Int
		s          *big.Int
		v          *big.Int
		chainID    *big.Int
		expectedV  byte
		wantErr    bool
	}{
		{name: "modern V=0", r: r, s: s, v: big.NewInt(0), chainID: nil, expectedV: 0},
		{name: "modern V=1", r: r, s: s, v: big.NewInt(1), chainID: nil, expectedV: 1},
		{name: "pre-EIP-155 V=27", r: r, s: s, v: big.NewInt(27), chainID: nil, expectedV: 0},
		{name: "pre-EIP-155 V=28", r: r, s: s, v: big.NewInt(28), chainID: nil, expectedV: 1},
		{name: "EIP-155 chainID=1 V=37", r: r, s: s, v: big.NewInt(37), chainID: big.NewInt(1), expectedV: 0},
		{name: "EIP-155 chainID=1 V=38", r: r, s: s, v: big.NewInt(38), chainID: big.NewInt(1), expectedV: 1},
		{name: "EIP-155 chainID=137 V=309", r: r, s: s, v: big.NewInt(309), chainID: big.NewInt(137), expectedV: 0},
		{name: "EIP-155 chainID=137 V=310", r: r, s: s, v: big.NewInt(310), chainID: big.NewInt(137), expectedV: 1},
		{name: "nil r", r: nil, s: s, v: big.NewInt(0), chainID: nil, wantErr: true},
		{name: "nil s", r: r, s: nil, v: big.NewInt(0), chainID: nil, wantErr: true},
		{name: "nil v", r: r, s: s, v: nil, chainID: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := EncodeSignature(tt.r, tt.s, tt.v, tt.chainID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("EncodeSignature() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeSignature() unexpected error: %v", err)
			}
			if len(sig) != 65 {
				t.Fatalf("EncodeSignature() signature length = %d, expected 65", len(sig))
			}
			// Check recovery ID byte
			if sig[64] != tt.expectedV {
				t.Errorf("EncodeSignature() V byte = %d, expected %d", sig[64], tt.expectedV)
			}
			// Check R bytes are correctly placed
			rBytes := tt.r.Bytes()
			for i, b := range rBytes {
				if sig[32-len(rBytes)+i] != b {
					t.Errorf("EncodeSignature() R byte mismatch at position %d", i)
					break
				}
			}
			// Check S bytes are correctly placed
			sBytes := tt.s.Bytes()
			for i, b := range sBytes {
				if sig[64-len(sBytes)+i] != b {
					t.Errorf("EncodeSignature() S byte mismatch at position %d", i)
					break
				}
			}
		})
	}
}

func TestVNormalization(t *testing.T) {
	// Test signature with V = 0 (should be normalized to 27)
	sigHex := "4fde044566e1288a60cebbc94458b2da86940d78ea2a92a993232726fb2ce78f797aef5eb003a2ca56ffec9e9cefe28f5666c352da36306c8ab807ac02d2f24400"
	sig, _ := hex.DecodeString(sigHex)

	_, _, v, err := ConvertSigBytes2RSV(sig)
	if err != nil {
		t.Fatalf("ConvertSigBytes2RSV failed: %v", err)
	}

	// V should be normalized to 27
	expectedV := uint8(27)
	if v != expectedV {
		t.Errorf("V normalization failed:\nExpected: %d\nGot:      %d", expectedV, v)
	}
}
