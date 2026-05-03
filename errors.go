package erc6492

import "errors"

var (
	// ErrNilCaller is returned when a verification path requires a caller but nil was provided.
	ErrNilCaller = errors.New("erc6492: nil caller")

	// ErrMalformedERC6492Signature is returned when an ERC-6492 wrapper is missing or cannot be ABI-decoded.
	ErrMalformedERC6492Signature = errors.New("erc6492: malformed ERC-6492 signature")

	// ErrMissingERC6492Factory is returned when an unwrapped ERC-6492 signature is verified without factory data.
	ErrMissingERC6492Factory = errors.New("erc6492: missing ERC-6492 factory")

	// ErrMissingERC6492Verifier is returned when a deployed ERC-6492 verifier address is required but missing.
	ErrMissingERC6492Verifier = errors.New("erc6492: missing ERC-6492 verifier address")

	// ErrDeploylessVerifierMissing is returned when deployless ERC-6492 verification is requested before verifier bytecode provenance has been added.
	ErrDeploylessVerifierMissing = errors.New("erc6492: deployless verifier unavailable; provide WithERC6492VerifierAddress")

	// ErrInvalidABIOutput is returned when ABI encoding or return-data decoding fails.
	ErrInvalidABIOutput = errors.New("erc6492: invalid ABI output")

	// ErrUnexpectedVerifierData is returned when an ERC-6492 verifier returns data in an unexpected format.
	ErrUnexpectedVerifierData = errors.New("erc6492: unexpected verifier return data")
)
