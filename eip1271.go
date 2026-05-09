package erc6492

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// VerifyEIP1271 verifies a signature against a deployed smart contract wallet
// using EIP-1271 isValidSignature(bytes32,bytes).
//
// Invalid signatures return Result{Valid:false, Method: MethodEIP1271}, nil.
//
// A wrong magic value or contract revert is treated as a clean invalid
// signature. RPC failures, ABI failures, and malformed return data are errors.
func VerifyEIP1271(
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

	input, err := encodeEIP1271Call(hash, signature)
	if err != nil {
		return Result{}, fmt.Errorf("%w: encode eip1271 calldata: %v", ErrInvalidABIInput, err)
	}

	call := ethereum.CallMsg{
		To:   &signer,
		Data: input,
	}
	if cfg.hasFrom {
		call.From = cfg.from
	}

	output, err := caller.CallContract(ctx, call, copyBigInt(cfg.blockNumber))
	if err != nil {
		if isContractRevert(err) {
			return Result{Valid: false, Method: MethodEIP1271}, nil
		}

		return Result{}, fmt.Errorf("eip1271 call failed: %w", err)
	}

	magic, err := decodeEIP1271MagicValue(output)
	if err != nil {
		return Result{}, err
	}

	if !bytes.Equal(magic[:], eip1271MagicValue[:]) {
		return Result{Valid: false, Method: MethodEIP1271}, nil
	}

	return Result{Valid: true, Method: MethodEIP1271}, nil
}

func encodeEIP1271Call(hash common.Hash, signature []byte) ([]byte, error) {
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytesType},
	}

	encodedArgs, err := args.Pack(hash, append([]byte(nil), signature...))
	if err != nil {
		return nil, err
	}

	input := make([]byte, 0, len(eip1271IsValidSignatureSelector)+len(encodedArgs))
	input = append(input, eip1271IsValidSignatureSelector[:]...)
	input = append(input, encodedArgs...)

	return input, nil
}

func decodeEIP1271MagicValue(output []byte) ([4]byte, error) {
	bytes4Type, err := abi.NewType("bytes4", "", nil)
	if err != nil {
		return [4]byte{}, err
	}

	args := abi.Arguments{
		{Type: bytes4Type},
	}

	values, err := args.Unpack(output)
	if err != nil {
		return [4]byte{}, fmt.Errorf("%w: decode eip1271 return data: %v", ErrInvalidABIOutput, err)
	}

	if len(values) != 1 {
		return [4]byte{}, fmt.Errorf("%w: decode eip1271 return data: expected 1 value, got %d", ErrInvalidABIOutput, len(values))
	}

	magic, ok := values[0].([4]byte)
	if !ok {
		return [4]byte{}, fmt.Errorf("%w: decode eip1271 return data: magic value has type %T", ErrInvalidABIOutput, values[0])
	}

	return magic, nil
}

func isContractRevert(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, vm.ErrExecutionReverted) {
		return true
	}

	// Some RPC clients or wrapper libraries expose EVM reverts as plain
	// error messages instead of preserving vm.ErrExecutionReverted.
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "execution reverted")
}
