package erc6492

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// WrappedSignature is the decoded ERC-6492 wrapper payload.
//
// The encoded ERC-6492 payload is:
//
//	(address factory, bytes factoryData, bytes signature)
//
// followed by the ERC-6492 magic suffix.
type WrappedSignature struct {
	Factory     common.Address
	FactoryData []byte
	Signature   []byte
}

// VerifyERC6492 verifies a signature using a deployed ERC-6492 verifier.
//
// It supports:
//   - already-wrapped ERC-6492 signatures,
//   - unwrapped signatures plus WithERC6492Factory,
//   - deployed verifier calls via WithERC6492VerifierAddress.
func VerifyERC6492(
	ctx context.Context,
	caller ContractCaller,
	signer common.Address,
	hash common.Hash,
	signature []byte,
	opts ...VerifyOption,
) (Result, error) {
	if caller == nil {
		return Result{}, ErrNilCaller
	}

	cfg := applyVerifyOptions(opts)

	wrappedSignature := signature

	if IsERC6492Signature(signature) {
		if _, err := UnwrapERC6492(signature); err != nil {
			return Result{}, err
		}
	} else {
		if !cfg.hasERC6492Factory {
			return Result{}, ErrMissingERC6492Factory
		}

		wrapped, err := WrapERC6492(cfg.erc6492Factory, cfg.erc6492FactoryData, signature)
		if err != nil {
			return Result{}, err
		}

		wrappedSignature = wrapped
	}

	if !cfg.hasERC6492VerifierAddress {
		return Result{}, ErrDeploylessVerifierMissing
	}

	input, err := encodeERC6492VerifierCall(signer, hash, wrappedSignature)
	if err != nil {
		return Result{}, fmt.Errorf("%w: encode erc6492 verifier calldata: %v", ErrInvalidABIOutput, err)
	}

	call := ethereum.CallMsg{
		To:   &cfg.erc6492VerifierAddress,
		Data: input,
	}
	if cfg.hasFrom {
		call.From = cfg.from
	}

	output, err := caller.CallContract(ctx, call, copyBigInt(cfg.blockNumber))
	if err != nil {
		return Result{}, fmt.Errorf("erc6492 verifier call failed: %w", err)
	}

	valid, err := decodeERC6492VerifierResult(output)
	if err != nil {
		return Result{}, err
	}

	if !valid {
		return Result{Valid: false, Method: MethodERC6492}, nil
	}

	return Result{Valid: true, Method: MethodERC6492}, nil
}

// IsERC6492Signature reports whether signature ends with the ERC-6492 magic suffix.
func IsERC6492Signature(signature []byte) bool {
	if len(signature) < len(erc6492MagicSuffix) {
		return false
	}

	return bytes.Equal(signature[len(signature)-len(erc6492MagicSuffix):], erc6492MagicSuffix[:])
}

// IsWrappedSignature is an alias for IsERC6492Signature.
func IsWrappedSignature(signature []byte) bool {
	return IsERC6492Signature(signature)
}

// WrapERC6492 ABI-encodes an ERC-6492 wrapper payload and appends the
// ERC-6492 magic suffix.
//
// The encoded payload is:
//
//	(address factory, bytes factoryData, bytes signature)
func WrapERC6492(
	factory common.Address,
	factoryData []byte,
	signature []byte,
) ([]byte, error) {
	payload, err := encodeERC6492Wrapper(factory, factoryData, signature)
	if err != nil {
		return nil, fmt.Errorf("%w: encode erc6492 wrapper: %v", ErrMalformedERC6492Signature, err)
	}

	wrapped := make([]byte, 0, len(payload)+len(erc6492MagicSuffix))
	wrapped = append(wrapped, payload...)
	wrapped = append(wrapped, erc6492MagicSuffix[:]...)

	return wrapped, nil
}

// UnwrapERC6492 decodes an ERC-6492 wrapped signature.
//
// The input must end with the ERC-6492 magic suffix. The payload before the
// suffix must ABI-decode as:
//
//	(address factory, bytes factoryData, bytes signature)
func UnwrapERC6492(signature []byte) (WrappedSignature, error) {
	if !IsERC6492Signature(signature) {
		return WrappedSignature{}, ErrMalformedERC6492Signature
	}

	payload := signature[:len(signature)-len(erc6492MagicSuffix)]

	wrapped, err := decodeERC6492Wrapper(payload)
	if err != nil {
		return WrappedSignature{}, fmt.Errorf("%w: decode erc6492 wrapper: %v", ErrMalformedERC6492Signature, err)
	}

	return wrapped, nil
}

func encodeERC6492VerifierCall(
	signer common.Address,
	hash common.Hash,
	signature []byte,
) ([]byte, error) {
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	args := abi.Arguments{
		{Type: addressType},
		{Type: bytes32Type},
		{Type: bytesType},
	}

	encodedArgs, err := args.Pack(
		signer,
		hash,
		append([]byte(nil), signature...),
	)
	if err != nil {
		return nil, err
	}

	input := make([]byte, 0, len(erc6492VerifierSelector)+len(encodedArgs))
	input = append(input, erc6492VerifierSelector[:]...)
	input = append(input, encodedArgs...)

	return input, nil
}

func decodeERC6492VerifierResult(output []byte) (bool, error) {
	boolType, err := abi.NewType("bool", "", nil)
	if err != nil {
		return false, err
	}

	args := abi.Arguments{
		{Type: boolType},
	}

	values, err := args.Unpack(output)
	if err != nil {
		return false, fmt.Errorf("%w: decode erc6492 verifier return data: %v", ErrUnexpectedVerifierData, err)
	}

	if len(values) != 1 {
		return false, fmt.Errorf("%w: decode erc6492 verifier return data: expected 1 value, got %d", ErrUnexpectedVerifierData, len(values))
	}

	valid, ok := values[0].(bool)
	if !ok {
		return false, fmt.Errorf("%w: decode erc6492 verifier return data: verifier result has type %T", ErrUnexpectedVerifierData, values[0])
	}

	return valid, nil
}
