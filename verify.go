package erc6492

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// ContractCaller is the minimal interface required to perform eth_call-style
// contract calls.
type ContractCaller interface {
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// ContractCodeReader is the minimal interface required to read contract code.
type ContractCodeReader interface {
	CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error)
}

// Caller combines the minimal interfaces required by universal verification.
type Caller interface {
	ContractCaller
	ContractCodeReader
}

// Verify verifies a signature against an already-computed hash using the
// universal verification order:
//
//	ERC-6492 wrapped signature
//	→ WithERC6492Factory wrapping path
//	→ EIP-1271 if signer has code
//	→ EOA fallback
//
// If signer has code and EIP-1271 returns a clean invalid result, Verify falls
// back to EOA verification. RPC failures, ABI failures, malformed input, and
// unexpected verifier results are returned as errors.
func Verify(
	ctx context.Context,
	caller Caller,
	signer common.Address,
	hash common.Hash,
	signature []byte,
	opts ...VerifyOption,
) (Result, error) {
	if caller == nil {
		return Result{}, ErrNilCaller
	}

	cfg := applyVerifyOptions(opts)

	if IsERC6492Signature(signature) {
		return VerifyERC6492(ctx, caller, signer, hash, signature, opts...)
	}

	if cfg.hasERC6492Factory {
		return VerifyERC6492(ctx, caller, signer, hash, signature, opts...)
	}

	code, err := caller.CodeAt(ctx, signer, copyBigInt(cfg.blockNumber))
	if err != nil {
		return Result{}, fmt.Errorf("read signer code: %w", err)
	}

	if len(code) > 0 {
		result, err := VerifyEIP1271(ctx, caller, signer, hash, signature, opts...)
		if err != nil {
			return Result{}, err
		}

		if result.Valid {
			return result, nil
		}

		return VerifyEOA(signer, hash, signature)
	}

	return VerifyEOA(signer, hash, signature)
}
