package erc6492

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// VerifyEOA verifies a 65-byte Ethereum EOA signature against an already-computed hash.
//
// Invalid signatures return Result{Valid:false, Method: MethodEOA}, nil.
// Malformed EOA signature values such as bad length, bad v, high-s, or failed
// recovery are treated as invalid signatures rather than errors.
func VerifyEOA(
	signer common.Address,
	hash common.Hash,
	signature []byte,
) (Result, error) {
	if len(signature) != 65 {
		return Result{Valid: false, Method: MethodEOA}, nil
	}

	sig := append([]byte(nil), signature...)

	switch sig[64] {
	case 27, 28:
		sig[64] -= 27
	case 0, 1:
		// Already normalized for go-ethereum recovery.
	default:
		return Result{Valid: false, Method: MethodEOA}, nil
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return Result{Valid: false, Method: MethodEOA}, nil
	}

	pubkey, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return Result{Valid: false, Method: MethodEOA}, nil
	}

	recovered := crypto.PubkeyToAddress(*pubkey)
	if recovered != signer {
		return Result{Valid: false, Method: MethodEOA}, nil
	}

	return Result{Valid: true, Method: MethodEOA}, nil
}
