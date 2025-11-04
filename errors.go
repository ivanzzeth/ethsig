package ethsig

import "errors"

// Common errors used throughout the package
var (
	// Signature errors
	ErrInvalidSignatureLen      = errors.New("invalid signature length")
	ErrInvalidEIP191MessagePrefix = errors.New("invalid EIP191 message prefix")
	ErrSignatureValidationFailed = errors.New("signature validation failed")
	ErrSignatureRecoveryFailed   = errors.New("signature recovery failed")

	// Signer errors
	ErrSignerNotImplemented     = errors.New("signer does not implement required interface")
	ErrSignerNotFound           = errors.New("signer not found")
	ErrSignerInvalidType        = errors.New("invalid signer type")
	ErrSignerAddressMismatch    = errors.New("address mismatch in signer")

	// Transaction errors
	ErrTransactionNil           = errors.New("transaction is nil")
	ErrChainIDNil               = errors.New("chainID is nil")
	ErrTransactionSignFailed    = errors.New("transaction signing failed")
	ErrTransactionInvalid       = errors.New("invalid transaction")

	// Keystore errors
	ErrKeystorePathEmpty        = errors.New("keystore path cannot be empty")
	ErrKeystoreNotFound         = errors.New("keystore file not found")
	ErrKeystoreDecryptFailed    = errors.New("keystore decryption failed")
	ErrKeystoreImportFailed     = errors.New("keystore import failed")
	ErrKeystoreDirectoryEmpty   = errors.New("keystore directory cannot be empty")
	ErrKeystoreNoFilesFound     = errors.New("no keystore files found in directory")
	ErrKeystoreCreateFailed     = errors.New("failed to create keystore")
	ErrKeystoreExportNotSupported = errors.New("private key export not supported with keystore-based implementation")

	// Validation errors
	ErrAddressZero              = errors.New("address is zero address")
	ErrAddressInvalid           = errors.New("invalid Ethereum address format")
	ErrChainIDInvalid           = errors.New("chainID must be positive")
	ErrMessageInvalid           = errors.New("invalid message format")
	ErrTypedDataInvalid         = errors.New("invalid typed data structure")

	// Cryptographic errors
	ErrCryptoOperationFailed    = errors.New("cryptographic operation failed")
	ErrPrivateKeyInvalid        = errors.New("invalid private key")
	ErrPublicKeyInvalid         = errors.New("invalid public key")
	ErrHashFailed               = errors.New("hash operation failed")

	// Security errors
	ErrSecurityViolation        = errors.New("security violation detected")
	ErrMemorySafety             = errors.New("memory safety violation")
	ErrTimingAttack             = errors.New("potential timing attack detected")

	// EIP-712 errors
	ErrEIP712DomainUndefined    = errors.New("domain is undefined")
	ErrEIP712HashFailed         = errors.New("failed to hash EIP-712 data")
	ErrEIP712TypeNotFound       = errors.New("EIP-712 type not found")
	ErrEIP712InvalidStructure   = errors.New("invalid EIP-712 structure")

	// Authorization errors
	ErrNotAuthorized            = errors.New("not authorized to perform operation")
	ErrPermissionDenied         = errors.New("permission denied")

	// Configuration errors
	ErrConfigurationInvalid     = errors.New("invalid configuration")
	ErrParameterMissing         = errors.New("required parameter missing")
	ErrParameterInvalid         = errors.New("invalid parameter value")
)

// Error types for better error categorization
type ErrorType int

const (
	ErrorTypeSignature ErrorType = iota
	ErrorTypeSigner
	ErrorTypeTransaction
	ErrorTypeKeystore
	ErrorTypeValidation
	ErrorTypeCryptographic
	ErrorTypeSecurity
	ErrorTypeEIP712
	ErrorTypeAuthorization
	ErrorTypeConfiguration
)

// TypedError represents a categorized error with additional context
type TypedError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// Error implements the error interface
func (e *TypedError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *TypedError) Unwrap() error {
	return e.Cause
}

// NewTypedError creates a new typed error
func NewTypedError(errorType ErrorType, message string, cause error) *TypedError {
	return &TypedError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// Error helper functions for common error patterns

// NewSignatureError creates a signature-related error
func NewSignatureError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeSignature, message, cause)
}

// NewSignerError creates a signer-related error
func NewSignerError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeSigner, message, cause)
}

// NewTransactionError creates a transaction-related error
func NewTransactionError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeTransaction, message, cause)
}

// NewKeystoreError creates a keystore-related error
func NewKeystoreError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeKeystore, message, cause)
}

// NewValidationError creates a validation-related error
func NewValidationError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeValidation, message, cause)
}

// NewSecurityError creates a security-related error
func NewSecurityError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeSecurity, message, cause)
}

// Error checking functions

// IsSignatureError checks if an error is signature-related
func IsSignatureError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeSignature
	}
	return false
}

// IsSignerError checks if an error is signer-related
func IsSignerError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeSigner
	}
	return false
}

// IsTransactionError checks if an error is transaction-related
func IsTransactionError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeTransaction
	}
	return false
}

// IsKeystoreError checks if an error is keystore-related
func IsKeystoreError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeKeystore
	}
	return false
}

// IsValidationError checks if an error is validation-related
func IsValidationError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeValidation
	}
	return false
}

// IsSecurityError checks if an error is security-related
func IsSecurityError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeSecurity
	}
	return false
}

// NewEIP712Error creates an EIP-712 related error
func NewEIP712Error(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeEIP712, message, cause)
}

// NewAuthorizationError creates an authorization-related error
func NewAuthorizationError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeAuthorization, message, cause)
}

// NewConfigurationError creates a configuration-related error
func NewConfigurationError(message string, cause error) *TypedError {
	return NewTypedError(ErrorTypeConfiguration, message, cause)
}

// IsEIP712Error checks if an error is EIP-712 related
func IsEIP712Error(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeEIP712
	}
	return false
}

// IsAuthorizationError checks if an error is authorization-related
func IsAuthorizationError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeAuthorization
	}
	return false
}

// IsConfigurationError checks if an error is configuration-related
func IsConfigurationError(err error) bool {
	if typedErr, ok := err.(*TypedError); ok {
		return typedErr.Type == ErrorTypeConfiguration
	}
	return false
}
