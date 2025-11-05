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

- **Advanced Whitelist System**
  - Transaction whitelisting with method and recipient filtering
  - Parameter value constraints for function calls
  - EIP-712 field value constraints
  - Pattern matching and numeric range validation
  - Audit logging with detailed operation tracking

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

## Whitelist System

### How Whitelist Matching Works

**Important**: The whitelist uses **OR logic** - an operation is allowed if it matches **ANY** rule.

For each operation type (PersonalSign, EIP712, Transaction), the checker:
1. Iterates through all rules of that type
2. If **any single rule** matches, the operation is **immediately allowed**
3. If **no rules** match, the operation is **denied**

This allows you to add multiple rules for different scenarios:

```go
checker := ethsig.NewMemoryWhitelistChecker()

// Add multiple rules - operation passes if ANY rule matches
checker.AddPersonalSignRule(PersonalSignWhitelistRule{
    ID:              "login-messages",
    AllowedPrefixes: []string{"Login to"},
})

checker.AddPersonalSignRule(PersonalSignWhitelistRule{
    ID:              "confirm-messages",
    AllowedPrefixes: []string{"Confirm action"},
})

// ✓ "Login to app" passes (matches login-messages rule)
// ✓ "Confirm action #123" passes (matches confirm-messages rule)
// ✗ "Random message" fails (matches no rules)
```

### Basic Transaction Whitelist

See [examples/whitelist_basic/main.go](examples/whitelist_basic/main.go) for a complete example.

### Transaction with Parameter Constraints

See [examples/whitelist_param_constraints/main.go](examples/whitelist_param_constraints/main.go) for a complete example.

### Approve with Spender Whitelist

See [examples/whitelist_approve/main.go](examples/whitelist_approve/main.go) for a complete example.

### EIP-712 with Field Value Constraints

See [examples/eip712_whitelist/main.go](examples/eip712_whitelist/main.go) for a complete example.

### Multiple Field Constraints

This example is included in [examples/eip712_whitelist/main.go](examples/eip712_whitelist/main.go).

### Pattern Matching for Strings

See [examples/eip712_pattern_matching/main.go](examples/eip712_pattern_matching/main.go) for a complete example.

## Constraint Types

### Parameter Constraints

Parameter constraints apply to transaction function call parameters:

- **Index**: Zero-based parameter position (0 = first param, 1 = second param, etc.)
- **AllowedValues**: List of specific allowed values
- **MinValue**: Minimum numeric value (for uint256, int256, etc.)
- **MaxValue**: Maximum numeric value
- **AllowedPattern**: Regex pattern for validation

### Field Constraints

Field constraints apply to EIP-712 typed data message fields:

- **FieldName**: Name of the field to constrain
- **AllowedValues**: List of specific allowed values
- **MinValue**: Minimum numeric value
- **MaxValue**: Maximum numeric value
- **AllowedPattern**: Regex pattern for string fields

## Interfaces

The library provides several interfaces for flexibility:

```go
// AddressGetter provides address retrieval
type AddressGetter interface {
    GetAddress() common.Address
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

4. **Always use whitelists** in production to restrict operations:
   ```go
   protectedSigner := ethsig.NewWhitelistSigner(signer, checker)
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
