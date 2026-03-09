package keystore

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// testEd25519Seed is a known 32-byte seed for testing (DO NOT use in production).
var testEd25519Seed = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

var testEnhancedPassword = []byte("test-enhanced-password")

// --- ValidateKeyBytes tests ---

func TestValidateKeyBytes_Ed25519_Valid(t *testing.T) {
	if err := ValidateKeyBytes(testEd25519Seed, KeyTypeEd25519); err != nil {
		t.Errorf("expected valid ed25519 key, got: %v", err)
	}
}

func TestValidateKeyBytes_Ed25519_WrongSize(t *testing.T) {
	short := make([]byte, 16)
	if err := ValidateKeyBytes(short, KeyTypeEd25519); err == nil {
		t.Error("expected error for wrong size ed25519 key")
	}

	long := make([]byte, 64)
	if err := ValidateKeyBytes(long, KeyTypeEd25519); err == nil {
		t.Error("expected error for wrong size ed25519 key")
	}
}

func TestValidateKeyBytes_Secp256k1_Valid(t *testing.T) {
	// Known Hardhat test key
	keyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err := ValidateKeyBytes(keyBytes, KeyTypeSecp256k1); err != nil {
		t.Errorf("expected valid secp256k1 key, got: %v", err)
	}
}

func TestValidateKeyBytes_Secp256k1_WrongSize(t *testing.T) {
	short := make([]byte, 16)
	if err := ValidateKeyBytes(short, KeyTypeSecp256k1); err == nil {
		t.Error("expected error for wrong size secp256k1 key")
	}
}

func TestValidateKeyBytes_AllZeros(t *testing.T) {
	zeros := make([]byte, 32)
	if err := ValidateKeyBytes(zeros, KeyTypeEd25519); err == nil {
		t.Error("expected error for all-zero key")
	}
}

func TestValidateKeyBytes_ExceedsN(t *testing.T) {
	// Create a key that is >= secp256k1 N
	nBytes := secp256k1N.Bytes()
	if err := ValidateKeyBytes(nBytes, KeyTypeEd25519); err == nil {
		t.Error("expected error for key >= N")
	}

	// N + 1
	nPlus1 := new(big.Int).Add(secp256k1N, big.NewInt(1))
	if err := ValidateKeyBytes(nPlus1.Bytes(), KeyTypeEd25519); err == nil {
		t.Error("expected error for key > N")
	}
}

func TestValidateKeyBytes_UnsupportedType(t *testing.T) {
	if err := ValidateKeyBytes(testEd25519Seed, KeyType("rsa")); err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// --- ParseKeyInput tests ---

func TestParseKeyInput_Hex(t *testing.T) {
	hexStr := hex.EncodeToString(testEd25519Seed)
	result, err := ParseKeyInput([]byte(hexStr), KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput hex failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_Hex_With0xPrefix(t *testing.T) {
	hexStr := "0x" + hex.EncodeToString(testEd25519Seed)
	result, err := ParseKeyInput([]byte(hexStr), KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput hex with 0x failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_Hex_WithWhitespace(t *testing.T) {
	hexStr := "  " + hex.EncodeToString(testEd25519Seed) + "  \n"
	result, err := ParseKeyInput([]byte(hexStr), KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput hex with whitespace failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_InvalidHex(t *testing.T) {
	_, err := ParseKeyInput([]byte("not-valid-hex!"), KeyFormatHex, KeyTypeEd25519)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseKeyInput_Base64(t *testing.T) {
	b64Str := base64.StdEncoding.EncodeToString(testEd25519Seed)
	result, err := ParseKeyInput([]byte(b64Str), KeyFormatBase64, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput base64 failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_Base64_RawNoPadding(t *testing.T) {
	b64Str := base64.RawStdEncoding.EncodeToString(testEd25519Seed)
	result, err := ParseKeyInput([]byte(b64Str), KeyFormatBase64, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput raw base64 failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_InvalidBase64(t *testing.T) {
	_, err := ParseKeyInput([]byte("!!!not-base64!!!"), KeyFormatBase64, KeyTypeEd25519)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestParseKeyInput_PEM_PKCS8_Ed25519(t *testing.T) {
	privKey := ed25519.NewKeyFromSeed(testEd25519Seed)
	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	result, err := ParseKeyInput(pemBytes, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput PEM PKCS8 failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Errorf("parsed seed does not match original: got %x, want %x", result, testEd25519Seed)
	}
}

func TestParseKeyInput_PEM_RawBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: testEd25519Seed,
	})

	result, err := ParseKeyInput(pemBytes, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput PEM raw failed: %v", err)
	}
	if !bytesEqual(result, testEd25519Seed) {
		t.Error("parsed bytes do not match original")
	}
}

func TestParseKeyInput_InvalidPEM(t *testing.T) {
	_, err := ParseKeyInput([]byte("not a PEM block"), KeyFormatPEM, KeyTypeEd25519)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParseKeyInput_UnsupportedFormat(t *testing.T) {
	_, err := ParseKeyInput([]byte("data"), KeyFormat("yaml"), KeyTypeEd25519)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// --- FormatKeyOutput tests ---

func TestFormatKeyOutput_Hex(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput hex failed: %v", err)
	}
	expected := hex.EncodeToString(testEd25519Seed)
	if string(output) != expected {
		t.Errorf("hex output = %s, want %s", string(output), expected)
	}
}

func TestFormatKeyOutput_Base64(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatBase64, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput base64 failed: %v", err)
	}
	expected := base64.StdEncoding.EncodeToString(testEd25519Seed)
	if string(output) != expected {
		t.Errorf("base64 output = %s, want %s", string(output), expected)
	}
}

func TestFormatKeyOutput_PEM_Ed25519(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput PEM failed: %v", err)
	}

	// Verify it's valid PEM
	block, _ := pem.Decode(output)
	if block == nil {
		t.Fatal("output is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM type = %s, want PRIVATE KEY", block.Type)
	}

	// Verify it's valid PKCS8
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}
	edKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", privKey)
	}
	if !bytesEqual(edKey.Seed(), testEd25519Seed) {
		t.Error("PEM round-trip seed mismatch")
	}
}

func TestFormatKeyOutput_UnsupportedFormat(t *testing.T) {
	_, err := FormatKeyOutput(testEd25519Seed, KeyFormat("yaml"), KeyTypeEd25519)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// --- Format round-trip tests ---

func TestFormatRoundTrip_Hex(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput failed: %v", err)
	}
	parsed, err := ParseKeyInput(output, KeyFormatHex, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput failed: %v", err)
	}
	if !bytesEqual(parsed, testEd25519Seed) {
		t.Error("hex round-trip failed")
	}
}

func TestFormatRoundTrip_Base64(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatBase64, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput failed: %v", err)
	}
	parsed, err := ParseKeyInput(output, KeyFormatBase64, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput failed: %v", err)
	}
	if !bytesEqual(parsed, testEd25519Seed) {
		t.Error("base64 round-trip failed")
	}
}

func TestFormatRoundTrip_PEM_Ed25519(t *testing.T) {
	output, err := FormatKeyOutput(testEd25519Seed, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("FormatKeyOutput failed: %v", err)
	}
	parsed, err := ParseKeyInput(output, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput failed: %v", err)
	}
	if !bytesEqual(parsed, testEd25519Seed) {
		t.Error("PEM round-trip failed")
	}
}

// --- CreateEnhancedKey tests ---

func TestCreateEnhancedKey_Ed25519(t *testing.T) {
	dir := t.TempDir()

	identifier, path, err := CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("CreateEnhancedKey failed: %v", err)
	}

	if identifier == "" {
		t.Error("identifier should not be empty")
	}

	// ed25519 public key is 32 bytes = 64 hex chars
	if len(identifier) != 64 {
		t.Errorf("ed25519 identifier should be 64 hex chars, got %d", len(identifier))
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("enhanced key file does not exist at %s", path)
	}

	// Verify filename format
	expectedFileName := enhancedKeyFileName(KeyTypeEd25519, identifier)
	if filepath.Base(path) != expectedFileName {
		t.Errorf("filename = %s, want %s", filepath.Base(path), expectedFileName)
	}

	// Verify metadata
	info, err := GetEnhancedKeyInfo(path)
	if err != nil {
		t.Fatalf("GetEnhancedKeyInfo failed: %v", err)
	}
	if info.KeyType != KeyTypeEd25519 {
		t.Errorf("key type = %s, want %s", info.KeyType, KeyTypeEd25519)
	}
	if info.Identifier != identifier {
		t.Errorf("identifier mismatch")
	}
}

func TestCreateEnhancedKey_Ed25519_WithLabel(t *testing.T) {
	dir := t.TempDir()

	_, path, err := CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "my-auth-key")
	if err != nil {
		t.Fatalf("CreateEnhancedKey failed: %v", err)
	}

	info, err := GetEnhancedKeyInfo(path)
	if err != nil {
		t.Fatalf("GetEnhancedKeyInfo failed: %v", err)
	}
	if info.Label != "my-auth-key" {
		t.Errorf("label = %q, want %q", info.Label, "my-auth-key")
	}
}

func TestCreateEnhancedKey_EmptyDir(t *testing.T) {
	_, _, err := CreateEnhancedKey("", KeyTypeEd25519, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for empty dir")
	}
}

func TestCreateEnhancedKey_EmptyPassword(t *testing.T) {
	dir := t.TempDir()
	_, _, err := CreateEnhancedKey(dir, KeyTypeEd25519, nil, "")
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestCreateEnhancedKey_UnsupportedType(t *testing.T) {
	dir := t.TempDir()
	_, _, err := CreateEnhancedKey(dir, KeyTypeSecp256k1, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for secp256k1 (should use native keystore)")
	}
}

func TestCreateEnhancedKey_UnsupportedTypeRSA(t *testing.T) {
	dir := t.TempDir()
	_, _, err := CreateEnhancedKey(dir, KeyType("rsa"), testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// --- ImportEnhancedKey tests ---

func TestImportEnhancedKey_Ed25519_Hex(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	identifier, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "test-label")
	if err != nil {
		t.Fatalf("ImportEnhancedKey hex failed: %v", err)
	}

	if identifier == "" {
		t.Error("identifier should not be empty")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("file not created at %s", path)
	}

	// Verify password works
	if err := VerifyEnhancedKeyPassword(path, testEnhancedPassword); err != nil {
		t.Errorf("VerifyEnhancedKeyPassword failed: %v", err)
	}
}

func TestImportEnhancedKey_Ed25519_Base64(t *testing.T) {
	dir := t.TempDir()
	b64Input := []byte(base64.StdEncoding.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, b64Input, KeyTypeEd25519, KeyFormatBase64, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("ImportEnhancedKey base64 failed: %v", err)
	}

	if err := VerifyEnhancedKeyPassword(path, testEnhancedPassword); err != nil {
		t.Errorf("VerifyEnhancedKeyPassword failed: %v", err)
	}
}

func TestImportEnhancedKey_Ed25519_PEM(t *testing.T) {
	dir := t.TempDir()

	privKey := ed25519.NewKeyFromSeed(testEd25519Seed)
	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	pemInput := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	_, path, err := ImportEnhancedKey(dir, pemInput, KeyTypeEd25519, KeyFormatPEM, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("ImportEnhancedKey PEM failed: %v", err)
	}

	if err := VerifyEnhancedKeyPassword(path, testEnhancedPassword); err != nil {
		t.Errorf("VerifyEnhancedKeyPassword failed: %v", err)
	}
}

func TestImportEnhancedKey_EmptyInput(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ImportEnhancedKey(dir, nil, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestImportEnhancedKey_EmptyDir(t *testing.T) {
	_, _, err := ImportEnhancedKey("", []byte("deadbeef"), KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for empty dir")
	}
}

func TestImportEnhancedKey_EmptyPassword(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ImportEnhancedKey(dir, []byte(hex.EncodeToString(testEd25519Seed)), KeyTypeEd25519, KeyFormatHex, nil, "")
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestImportEnhancedKey_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ImportEnhancedKey(dir, []byte("data"), KeyTypeEd25519, KeyFormat("yaml"), testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestImportEnhancedKey_ValidationFailure_AllZeros(t *testing.T) {
	dir := t.TempDir()
	zeros := make([]byte, 32)
	hexInput := []byte(hex.EncodeToString(zeros))
	_, _, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for all-zero key")
	}
}

func TestImportEnhancedKey_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, _, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("first import failed: %v", err)
	}

	_, _, err = ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err == nil {
		t.Error("expected error for duplicate import")
	}
}

// --- ExportEnhancedKey tests ---

func TestExportEnhancedKey_Hex(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	exported, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatHex)
	if err != nil {
		t.Fatalf("ExportEnhancedKey hex failed: %v", err)
	}

	if string(exported) != hex.EncodeToString(testEd25519Seed) {
		t.Errorf("exported hex = %s, want %s", string(exported), hex.EncodeToString(testEd25519Seed))
	}
}

func TestExportEnhancedKey_Base64(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	exported, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatBase64)
	if err != nil {
		t.Fatalf("ExportEnhancedKey base64 failed: %v", err)
	}

	expected := base64.StdEncoding.EncodeToString(testEd25519Seed)
	if string(exported) != expected {
		t.Errorf("exported base64 = %s, want %s", string(exported), expected)
	}
}

func TestExportEnhancedKey_PEM(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	exported, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatPEM)
	if err != nil {
		t.Fatalf("ExportEnhancedKey PEM failed: %v", err)
	}

	// Verify PEM can be parsed back to original seed
	block, _ := pem.Decode(exported)
	if block == nil {
		t.Fatal("exported PEM is invalid")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}
	edKey := privKey.(ed25519.PrivateKey)
	if !bytesEqual(edKey.Seed(), testEd25519Seed) {
		t.Error("PEM export seed mismatch")
	}
}

func TestExportEnhancedKey_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	_, err = ExportEnhancedKey(path, []byte("wrong-password"), KeyFormatHex)
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestExportEnhancedKey_EmptyPath(t *testing.T) {
	_, err := ExportEnhancedKey("", testEnhancedPassword, KeyFormatHex)
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestExportEnhancedKey_EmptyPassword(t *testing.T) {
	_, err := ExportEnhancedKey("/some/path", nil, KeyFormatHex)
	if err == nil {
		t.Error("expected error for empty password")
	}
}

// --- Cross-format import/export round-trip ---

func TestImportExportRoundTrip_HexToBase64(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// Export as base64
	b64Output, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatBase64)
	if err != nil {
		t.Fatalf("export base64 failed: %v", err)
	}

	// Parse base64 back
	decoded, err := base64.StdEncoding.DecodeString(string(b64Output))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if !bytesEqual(decoded, testEd25519Seed) {
		t.Error("cross-format round-trip failed: hex -> base64")
	}
}

func TestImportExportRoundTrip_Base64ToPEM(t *testing.T) {
	dir := t.TempDir()
	b64Input := []byte(base64.StdEncoding.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, b64Input, KeyTypeEd25519, KeyFormatBase64, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	pemOutput, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatPEM)
	if err != nil {
		t.Fatalf("export PEM failed: %v", err)
	}

	// Parse PEM back to seed
	parsed, err := ParseKeyInput(pemOutput, KeyFormatPEM, KeyTypeEd25519)
	if err != nil {
		t.Fatalf("ParseKeyInput PEM failed: %v", err)
	}
	if !bytesEqual(parsed, testEd25519Seed) {
		t.Error("cross-format round-trip failed: base64 -> PEM")
	}
}

func TestImportExportRoundTrip_PEMToHex(t *testing.T) {
	dir := t.TempDir()

	privKey := ed25519.NewKeyFromSeed(testEd25519Seed)
	derBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	pemInput := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})

	_, path, err := ImportEnhancedKey(dir, pemInput, KeyTypeEd25519, KeyFormatPEM, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import PEM failed: %v", err)
	}

	hexOutput, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatHex)
	if err != nil {
		t.Fatalf("export hex failed: %v", err)
	}

	expectedHex := hex.EncodeToString(testEd25519Seed)
	if string(hexOutput) != expectedHex {
		t.Errorf("cross-format round-trip PEM->hex: got %s, want %s", string(hexOutput), expectedHex)
	}
}

// --- GetEnhancedKeyInfo tests ---

func TestGetEnhancedKeyInfo(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	identifier, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "my-key")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	info, err := GetEnhancedKeyInfo(path)
	if err != nil {
		t.Fatalf("GetEnhancedKeyInfo failed: %v", err)
	}
	if info.KeyType != KeyTypeEd25519 {
		t.Errorf("key type = %s, want %s", info.KeyType, KeyTypeEd25519)
	}
	if info.Identifier != identifier {
		t.Errorf("identifier mismatch")
	}
	if info.Label != "my-key" {
		t.Errorf("label = %q, want %q", info.Label, "my-key")
	}
	if info.Path != path {
		t.Errorf("path = %q, want %q", info.Path, path)
	}
}

func TestGetEnhancedKeyInfo_EmptyPath(t *testing.T) {
	_, err := GetEnhancedKeyInfo("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestGetEnhancedKeyInfo_NonExistent(t *testing.T) {
	_, err := GetEnhancedKeyInfo("/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestGetEnhancedKeyInfo_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := GetEnhancedKeyInfo(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestGetEnhancedKeyInfo_MissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incomplete.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := GetEnhancedKeyInfo(path)
	if err == nil {
		t.Error("expected error for missing fields")
	}
}

// --- VerifyEnhancedKeyPassword tests ---

func TestVerifyEnhancedKeyPassword(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if err := VerifyEnhancedKeyPassword(path, testEnhancedPassword); err != nil {
		t.Errorf("correct password should verify: %v", err)
	}

	if err := VerifyEnhancedKeyPassword(path, []byte("wrong")); err == nil {
		t.Error("wrong password should fail verification")
	}
}

func TestVerifyEnhancedKeyPassword_EmptyPath(t *testing.T) {
	if err := VerifyEnhancedKeyPassword("", testEnhancedPassword); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestVerifyEnhancedKeyPassword_EmptyPassword(t *testing.T) {
	if err := VerifyEnhancedKeyPassword("/some/path", nil); err == nil {
		t.Error("expected error for empty password")
	}
}

// --- ChangeEnhancedKeyPassword tests ---

func TestChangeEnhancedKeyPassword(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	newPassword := []byte("new-password-456")
	if err := ChangeEnhancedKeyPassword(path, testEnhancedPassword, newPassword); err != nil {
		t.Fatalf("ChangeEnhancedKeyPassword failed: %v", err)
	}

	// Old password should fail
	if err := VerifyEnhancedKeyPassword(path, testEnhancedPassword); err == nil {
		t.Error("old password should no longer work")
	}

	// New password should work
	if err := VerifyEnhancedKeyPassword(path, newPassword); err != nil {
		t.Errorf("new password should work: %v", err)
	}

	// Data should be preserved
	exported, err := ExportEnhancedKey(path, newPassword, KeyFormatHex)
	if err != nil {
		t.Fatalf("export after password change failed: %v", err)
	}
	if string(exported) != hex.EncodeToString(testEd25519Seed) {
		t.Error("key data corrupted after password change")
	}
}

func TestChangeEnhancedKeyPassword_WrongCurrent(t *testing.T) {
	dir := t.TempDir()
	hexInput := []byte(hex.EncodeToString(testEd25519Seed))

	_, path, err := ImportEnhancedKey(dir, hexInput, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	err = ChangeEnhancedKeyPassword(path, []byte("wrong"), []byte("new"))
	if err == nil {
		t.Error("expected error for wrong current password")
	}
}

func TestChangeEnhancedKeyPassword_EmptyPath(t *testing.T) {
	err := ChangeEnhancedKeyPassword("", []byte("old"), []byte("new"))
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestChangeEnhancedKeyPassword_EmptyCurrent(t *testing.T) {
	err := ChangeEnhancedKeyPassword("/some/path", nil, []byte("new"))
	if err == nil {
		t.Error("expected error for empty current password")
	}
}

func TestChangeEnhancedKeyPassword_EmptyNew(t *testing.T) {
	err := ChangeEnhancedKeyPassword("/some/path", []byte("old"), nil)
	if err == nil {
		t.Error("expected error for empty new password")
	}
}

// --- ListEnhancedKeys tests ---

func TestListEnhancedKeys_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	keys, err := ListEnhancedKeys(dir)
	if err != nil {
		t.Fatalf("ListEnhancedKeys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestListEnhancedKeys(t *testing.T) {
	dir := t.TempDir()

	// Create two different ed25519 keys
	_, _, err := CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "key-1")
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	_, _, err = CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "key-2")
	if err != nil {
		t.Fatalf("second create failed: %v", err)
	}

	keys, err := ListEnhancedKeys(dir)
	if err != nil {
		t.Fatalf("ListEnhancedKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}

	// Verify all are ed25519
	for _, k := range keys {
		if k.KeyType != KeyTypeEd25519 {
			t.Errorf("expected ed25519, got %s", k.KeyType)
		}
	}
}

func TestListEnhancedKeys_EmptyDirPath(t *testing.T) {
	_, err := ListEnhancedKeys("")
	if err == nil {
		t.Error("expected error for empty dir")
	}
}

func TestListEnhancedKeys_NonExistentDir(t *testing.T) {
	_, err := ListEnhancedKeys("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for non-existent dir")
	}
}

// --- Mixed directory tests (backward compatibility) ---

func TestListEnhancedKeys_MixedDir_IgnoresNativeKeystores(t *testing.T) {
	dir := t.TempDir()

	// Create a native keystore
	_, _, err := CreateKeystore(dir, testEnhancedPassword)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	// Create an enhanced key
	_, _, err = CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("CreateEnhancedKey failed: %v", err)
	}

	// ListEnhancedKeys should only return the enhanced key
	enhancedKeys, err := ListEnhancedKeys(dir)
	if err != nil {
		t.Fatalf("ListEnhancedKeys failed: %v", err)
	}
	if len(enhancedKeys) != 1 {
		t.Errorf("expected 1 enhanced key, got %d", len(enhancedKeys))
	}
	if len(enhancedKeys) > 0 && enhancedKeys[0].KeyType != KeyTypeEd25519 {
		t.Errorf("expected ed25519, got %s", enhancedKeys[0].KeyType)
	}
}

func TestBackwardCompat_ListKeystoresIgnoresEnhanced(t *testing.T) {
	dir := t.TempDir()

	// Create a native keystore
	nativeAddr, _, err := CreateKeystore(dir, testEnhancedPassword)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	// Create an enhanced key
	_, _, err = CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("CreateEnhancedKey failed: %v", err)
	}

	// ListKeystores should only return the native keystore
	keystores, err := ListKeystores(dir)
	if err != nil {
		t.Fatalf("ListKeystores failed: %v", err)
	}
	if len(keystores) != 1 {
		t.Errorf("expected 1 native keystore, got %d", len(keystores))
	}
	if len(keystores) > 0 && keystores[0].Address != nativeAddr {
		t.Errorf("address mismatch: got %s, want %s", keystores[0].Address, nativeAddr)
	}
}

func TestBackwardCompat_NativeKeystoreUnchanged(t *testing.T) {
	dir := t.TempDir()
	password := []byte("test-password")

	// Create native keystore
	address, path, err := CreateKeystore(dir, password)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	// Verify it works exactly as before
	readAddr, err := GetKeystoreAddress(path)
	if err != nil {
		t.Fatalf("GetKeystoreAddress failed: %v", err)
	}
	if readAddr != address {
		t.Errorf("address mismatch: got %s, want %s", readAddr, address)
	}

	if err := VerifyPassword(path, password); err != nil {
		t.Errorf("VerifyPassword failed: %v", err)
	}

	// Import via native path
	privateKeyHex := []byte("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	expectedAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	importAddr, importPath, err := ImportPrivateKey(dir, privateKeyHex, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}
	if importAddr != expectedAddress {
		t.Errorf("import address = %s, want %s", importAddr, expectedAddress)
	}
	if err := VerifyPassword(importPath, password); err != nil {
		t.Errorf("VerifyPassword on imported key failed: %v", err)
	}
}

// --- ExportNativeKey tests ---

func TestExportNativeKey(t *testing.T) {
	dir := t.TempDir()
	password := []byte("test-password")

	privateKeyHex := []byte("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	_, path, err := ImportPrivateKey(dir, privateKeyHex, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}

	rawBytes, err := ExportNativeKey(path, password)
	if err != nil {
		t.Fatalf("ExportNativeKey failed: %v", err)
	}
	defer SecureZeroize(rawBytes)

	expectedBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if !bytesEqual(rawBytes, expectedBytes) {
		t.Errorf("exported bytes = %x, want %x", rawBytes, expectedBytes)
	}
}

func TestExportNativeKey_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	password := []byte("test-password")

	privateKeyHex := []byte("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	_, path, err := ImportPrivateKey(dir, privateKeyHex, password)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}

	_, err = ExportNativeKey(path, []byte("wrong"))
	if err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestExportNativeKey_EmptyPath(t *testing.T) {
	_, err := ExportNativeKey("", []byte("password"))
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestExportNativeKey_EmptyPassword(t *testing.T) {
	_, err := ExportNativeKey("/some/path", nil)
	if err == nil {
		t.Error("expected error for empty password")
	}
}

// --- IsEnhancedKeyFile tests ---

func TestIsEnhancedKeyFile(t *testing.T) {
	dir := t.TempDir()

	// Enhanced key file
	_, enhancedPath, err := CreateEnhancedKey(dir, KeyTypeEd25519, testEnhancedPassword, "")
	if err != nil {
		t.Fatalf("CreateEnhancedKey failed: %v", err)
	}
	if !IsEnhancedKeyFile(enhancedPath) {
		t.Error("enhanced key file should be detected as enhanced")
	}

	// Native keystore
	_, nativePath, err := CreateKeystore(dir, testEnhancedPassword)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}
	if IsEnhancedKeyFile(nativePath) {
		t.Error("native keystore should not be detected as enhanced")
	}

	// Non-existent file
	if IsEnhancedKeyFile("/nonexistent/file") {
		t.Error("non-existent file should not be detected as enhanced")
	}
}

// --- deriveIdentifier tests ---

func TestDeriveIdentifier_Ed25519(t *testing.T) {
	id := deriveIdentifier(testEd25519Seed, KeyTypeEd25519)
	// Should be hex of 32-byte public key = 64 hex chars
	if len(id) != 64 {
		t.Errorf("ed25519 identifier should be 64 hex chars, got %d", len(id))
	}

	// Verify it's the actual public key
	privKey := ed25519.NewKeyFromSeed(testEd25519Seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	expected := hex.EncodeToString(pubKey)
	if id != expected {
		t.Errorf("identifier = %s, want %s", id, expected)
	}
}

func TestDeriveIdentifier_Default(t *testing.T) {
	id := deriveIdentifier(testEd25519Seed, KeyType("unknown"))
	// SHA256 hash first 20 bytes = 40 hex chars
	if len(id) != 40 {
		t.Errorf("default identifier should be 40 hex chars, got %d", len(id))
	}
}

// --- enhancedKeyFileName tests ---

func TestEnhancedKeyFileName(t *testing.T) {
	name := enhancedKeyFileName(KeyTypeEd25519, "abc123")
	expected := "ed25519--abc123.json"
	if name != expected {
		t.Errorf("filename = %s, want %s", name, expected)
	}
}

// --- Edge case: fromFile simulation ---

func TestImportEnhancedKey_FromFile_Hex(t *testing.T) {
	dir := t.TempDir()

	// Write key to a file (simulating --from-file)
	keyFile := filepath.Join(dir, "key.hex")
	hexContent := hex.EncodeToString(testEd25519Seed)
	if err := os.WriteFile(keyFile, []byte(hexContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Read file and import
	fileContent, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	importDir := filepath.Join(dir, "keystores")
	_, path, err := ImportEnhancedKey(importDir, fileContent, KeyTypeEd25519, KeyFormatHex, testEnhancedPassword, "from-file")
	if err != nil {
		t.Fatalf("import from file failed: %v", err)
	}

	// Verify
	exported, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatHex)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if string(exported) != hexContent {
		t.Error("file import round-trip failed")
	}
}

func TestImportEnhancedKey_FromFile_PEM(t *testing.T) {
	dir := t.TempDir()

	// Write PEM key to a file
	privKey := ed25519.NewKeyFromSeed(testEd25519Seed)
	derBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	pemContent := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})

	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pemContent, 0600); err != nil {
		t.Fatal(err)
	}

	// Read file and import
	fileContent, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	importDir := filepath.Join(dir, "keystores")
	_, path, err := ImportEnhancedKey(importDir, fileContent, KeyTypeEd25519, KeyFormatPEM, testEnhancedPassword, "from-pem-file")
	if err != nil {
		t.Fatalf("import from PEM file failed: %v", err)
	}

	exported, err := ExportEnhancedKey(path, testEnhancedPassword, KeyFormatHex)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	expectedHex := hex.EncodeToString(testEd25519Seed)
	if string(exported) != expectedHex {
		t.Error("PEM file import round-trip failed")
	}
}
