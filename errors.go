package erc6492

import "errors"

var (
	// ErrNilCaller is returned when verification requires a caller but nil was provided.
	ErrNilCaller = errors.New("erc6492: nil caller")

	// ErrMalformedERC6492Signature is returned for missing or malformed ERC-6492 wrappers.
	ErrMalformedERC6492Signature = errors.New("erc6492: malformed ERC-6492 signature")

	// ErrMissingERC6492Factory is returned when an unwrapped signature cannot be
	// prepared for ERC-6492 verification because factory data was not provided.
	ErrMissingERC6492Factory = errors.New("erc6492: missing ERC-6492 factory")

	// ErrZeroERC6492FactoryAddress is returned when ERC-6492 wrapping is
	// requested with the zero factory address.
	ErrZeroERC6492FactoryAddress = errors.New("erc6492: zero ERC-6492 factory address")

	// ErrZeroERC6492VerifierAddress is returned when ERC-6492 verification is
	// configured with the zero verifier address.
	ErrZeroERC6492VerifierAddress = errors.New("erc6492: zero ERC-6492 verifier address")

	// ErrDeploylessVerifierMissing is returned when ERC-6492 verification needs
	// a verifier, but no deployed verifier was configured.
	ErrDeploylessVerifierMissing = errors.New("erc6492: deployless verifier unavailable; provide WithERC6492VerifierAddress")

	// ErrInvalidABIInput is returned when calldata cannot be ABI-encoded.
	ErrInvalidABIInput = errors.New("erc6492: invalid ABI input")

	// ErrInvalidABIOutput is returned when contract return data cannot be decoded.
	ErrInvalidABIOutput = errors.New("erc6492: invalid ABI output")

	// ErrUnexpectedVerifierData is returned when an ERC-6492 verifier returns
	// data that does not match the expected ABI.
	ErrUnexpectedVerifierData = errors.New("erc6492: unexpected verifier return data")
)
