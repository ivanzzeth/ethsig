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
go test ./... -timeout 30s

# Run specific package tests
go test -v ./... -run TestKeystore

# Run with race detection
go test -race ./...
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.
