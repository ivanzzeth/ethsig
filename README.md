# ethsig

A comprehensive Ethereum signature library for Go, providing secure signing operations with whitelist-based access control and parameter validation.

## Features

- **Multiple Signer Types**
  - Private key-based signing (`EthPrivateKeySigner`)
  - Keystore file-based signing (`KeystoreSigner`)
  - Configurable scrypt parameters for keystore encryption

- **Signing Standards Support**
  - Personal sign (EIP-191 version 0x45)
  - EIP-191 signed messages
  - EIP-712 typed structured data
  - Ethereum transaction signing

- **Multi-Key Keystore Management (CLI)**
  - Native go-ethereum keystore for secp256k1 (fully backward compatible)
  - Enhanced keystore for ed25519 and other key types
  - Multiple input/output formats: hex, base64, PEM
  - File-based import (`--from-file`)
  - Key metadata: type, identifier, label
  - BIP-39 HD wallet with key derivation

- **Security Features**
  - Secure memory handling for sensitive data
  - Configurable encryption strength
  - Fine-grained access control
  - Comprehensive validation

## Installation

```bash
go get github.com/ivanzzeth/ethsig
```

## Quick Start

### Basic Signing with Private Key

See [examples/basic_privatekey/main.go](examples/basic_privatekey/main.go) for a complete example.

### Using Keystore Signer

See [examples/keystore_signer/main.go](examples/keystore_signer/main.go) for a complete example.

### Custom Scrypt Configuration

See [examples/custom_scrypt_config/main.go](examples/custom_scrypt_config/main.go) for a complete example.

## Signing Operations

### Personal Sign (EIP-191)

See [examples/personal_sign/main.go](examples/personal_sign/main.go) for a complete example.

### EIP-712 Typed Data Signing

See [examples/eip712_signing/main.go](examples/eip712_signing/main.go) for a complete example.

### Transaction Signing

See [examples/transaction_signing/main.go](examples/transaction_signing/main.go) for a complete example.

## Keystore CLI

A command-line tool for managing encrypted keystores. Supports multiple key types and formats.

### Installation

```bash
go install github.com/ivanzzeth/ethsig/cmd/keystore@latest
```

### Key Types

| Type | Format | Identifier |
|------|--------|-----------|
| `secp256k1` (default) | Native go-ethereum keystore (`UTC--...`) | Ethereum address |
| `ed25519` | Enhanced keystore (`ed25519--{pubkey}.json`) | Public key hex |
| `p256` | Enhanced keystore (`p256--{compressed_pubkey}.json`) | Compressed public key hex |

### Commands

#### Create a new key

```bash
# secp256k1 (native, default)
keystore create -d ./keystores

# ed25519
keystore create -d ./keystores --key-type ed25519 --label "my-auth-key"

# p256 (secp256r1, for passkeys/WebAuthn/JWT ES256)
keystore create -d ./keystores --key-type p256 --label "my-passkey"
```

#### Import an existing key

```bash
# From interactive input (hex)
keystore import -d ./keystores --key-type ed25519 --format hex

# From base64 input
keystore import -d ./keystores --key-type ed25519 --format base64

# From PEM file
keystore import -d ./keystores --key-type ed25519 --format pem --from-file key.pem

# secp256k1 with base64 input
keystore import -d ./keystores --key-type secp256k1 --format base64
```

#### Export a key

```bash
# Export as hex
keystore export -k ./keystores/ed25519--abc123.json --format hex

# Export as PEM (PKCS8)
keystore export -k ./keystores/ed25519--abc123.json --format pem

# Export native keystore as base64
keystore export -k ./keystores/UTC--2024-...--address --format base64
```

#### List, show, verify, change password

```bash
# List all keystores (native + enhanced)
keystore list -d ./keystores

# Filter by key type
keystore list -d ./keystores --key-type ed25519
keystore list -d ./keystores --key-type secp256k1

# Show metadata without decryption
keystore show -k ./keystores/ed25519--abc123.json

# Verify password
keystore verify -k ./keystores/ed25519--abc123.json

# Change password (works with both native and enhanced)
keystore change-password -k ./keystores/ed25519--abc123.json
```

#### HD wallet commands

```bash
keystore hdwallet create -d ./hdwallets --entropy 128
keystore hdwallet import -d ./hdwallets
keystore hdwallet list -d ./hdwallets
keystore hdwallet derive -w ./hdwallets/hdwallet--0x123.json --start 0 --end 10
keystore hdwallet export-mnemonic -w ./hdwallets/hdwallet--0x123.json
```

### Enhanced Keystore JSON Format

```json
{
  "version": 1,
  "key_type": "ed25519",
  "identifier": "18088fb778ed804a9bac4e2cceb0f0fb6d2e1bb5a1871d0457f7b34a7f52755c",
  "crypto": { "...scrypt+AES encrypted key bytes..." },
  "label": "my-auth-key"
}
```

### Curve Order Validation

All key types are validated against the secp256k1 curve order N at import/create time. P-256 keys are additionally validated against the P-256 curve order N (which is smaller than secp256k1 N). The probability of a random key exceeding N is negligible (~2^-128), but if it occurs the tool reports an error and the user can regenerate.

## Interfaces

The library provides several interfaces for flexibility:

```go
// AddressGetter provides address retrieval
type AddressGetter interface {
    GetAddress() common.Address
}

// RawMessageSigner signs raw messages without hashing
type RawMessageSigner interface {
    SignRawMessage(raw []byte) ([]byte, error)
}

// HashSigner signs raw hashes
type HashSigner interface {
    SignHash(hashedData common.Hash) ([]byte, error)
}

// EIP191Signer signs EIP-191 formatted messages
type EIP191Signer interface {
    SignEIP191Message(message string) ([]byte, error)
}

// PersonalSigner signs personal messages
type PersonalSigner interface {
    PersonalSign(data string) ([]byte, error)
}

// TypedDataSigner signs EIP-712 typed data
type TypedDataSigner interface {
    SignTypedData(typedData eip712.TypedData) ([]byte, error)
}

// TransactionSigner signs transactions
type TransactionSigner interface {
    SignTransactionWithChainID(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// Signer combines all signing capabilities
type Signer interface {
    AddressGetter
    RawMessageSigner
    HashSigner
    EIP191Signer
    PersonalSigner
    TypedDataSigner
    TransactionSigner
}
```

## Security Best Practices

1. **Always close signers** when done to clear sensitive data from memory:
   ```go
   defer signer.Close()
   ```

2. **Use StandardScryptConfig for production** keystore files:
   ```go
   signer, err := ethsig.NewKeystoreSigner(path, password, &ethsig.StandardScryptConfig)
   ```

3. **Use LightScryptConfig for testing** to avoid timeouts:
   ```go
   signer, err := ethsig.NewKeystoreSigner(path, password, nil) // nil = LightScryptConfig
   ```

5. **Validate parameter and field values** using constraints to prevent unauthorized operations

6. **Store keystore files securely** with appropriate file permissions (0600)

7. **Never log or expose private keys** - use keystore files instead

## Testing

Run the test suite:

```bash
# Run all tests
go test ./...

# Run with timeout
go test ./... -timeout 300s

# Run specific package tests
go test -v ./keystore/ -run TestEnhanced
go test -v ./keystore/ -run TestBackwardCompat

# Run with coverage
go test ./keystore/ -coverprofile=coverage.out
go tool cover -func=coverage.out

# Run with race detection
go test -race ./...
```

## Security

### Git Hooks

Install pre-commit and pre-push security hooks:

```bash
./scripts/install-hooks.sh
```

**Pre-commit checks:**
- Error suppression detection (`_ = xxx` forbidden)
- `gosec` - static security analysis
- `govulncheck` - dependency vulnerability scanning
- `go vet` - code correctness
- Plaintext secret detection
- `gitleaks` - secret scanning in staged changes
- Full test suite

**Pre-push checks:**
- Full test suite with race detection (`go test -race ./...`)

### Security Audit

Run a comprehensive security audit:

```bash
./scripts/security-audit.sh
```

Checks: govulncheck, gosec, go module integrity, outdated dependencies.

### Required Tools

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/zricethezav/gitleaks/v8@latest
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.
