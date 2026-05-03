package erc6492

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestVerifyEOAValidSignatures(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	signer := cryptoAddressForTest(privateKey)

	tests := []struct {
		name    string
		adjustV func([]byte)
	}{
		{
			name: "v as 0 or 1",
			adjustV: func(signature []byte) {
				// crypto.Sign already returns v as 0 or 1.
			},
		},
		{
			name: "v as 27 or 28",
			adjustV: func(signature []byte) {
				signature[64] += 27
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := mustSignHash(t, hash, privateKey)
			tt.adjustV(signature)

			result, err := VerifyEOA(signer, hash, signature)
			assertNoError(t, err)
			assertResult(t, result, true, MethodEOA)
		})
	}
}

func TestVerifyEOAWrongSigner(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	otherPrivateKey := mustOtherTestPrivateKey(t)

	hash := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
	signature := mustSignHash(t, hash, privateKey)
	wrongSigner := cryptoAddressForTest(otherPrivateKey)

	result, err := VerifyEOA(wrongSigner, hash, signature)
	assertNoError(t, err)
	assertResult(t, result, false, MethodEOA)
}

func TestVerifyEOAWrongHash(t *testing.T) {
	privateKey := mustTestPrivateKey(t)

	signedHash := common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")
	checkedHash := common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555")
	signature := mustSignHash(t, signedHash, privateKey)
	signer := cryptoAddressForTest(privateKey)

	result, err := VerifyEOA(signer, checkedHash, signature)
	assertNoError(t, err)
	assertResult(t, result, false, MethodEOA)
}

func TestVerifyEOAInvalidSignatureLengths(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0x6666666666666666666666666666666666666666666666666666666666666666")
	validSignature := mustSignHash(t, hash, privateKey)
	signer := cryptoAddressForTest(privateKey)

	tests := []struct {
		name      string
		signature []byte
	}{
		{
			name:      "nil",
			signature: nil,
		},
		{
			name:      "empty",
			signature: []byte{},
		},
		{
			name:      "short",
			signature: validSignature[:64],
		},
		{
			name:      "long",
			signature: append(append([]byte(nil), validSignature...), 0x00),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := VerifyEOA(signer, hash, tt.signature)
			assertNoError(t, err)
			assertResult(t, result, false, MethodEOA)
		})
	}
}

func TestVerifyEOAInvalidV(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777")
	signer := cryptoAddressForTest(privateKey)

	tests := []struct {
		name string
		v    byte
	}{
		{
			name: "2",
			v:    2,
		},
		{
			name: "26",
			v:    26,
		},
		{
			name: "29",
			v:    29,
		},
		{
			name: "255",
			v:    255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := mustSignHash(t, hash, privateKey)
			signature[64] = tt.v

			result, err := VerifyEOA(signer, hash, signature)
			assertNoError(t, err)
			assertResult(t, result, false, MethodEOA)
		})
	}
}

func TestVerifyEOAHighS(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0x8888888888888888888888888888888888888888888888888888888888888888")
	signature := mustSignHash(t, hash, privateKey)
	signer := cryptoAddressForTest(privateKey)

	curveN := crypto.S256().Params().N
	s := new(big.Int).SetBytes(signature[32:64])
	highS := new(big.Int).Sub(curveN, s)

	highSBytes := highS.Bytes()
	for i := 32; i < 64; i++ {
		signature[i] = 0
	}
	copy(signature[64-len(highSBytes):64], highSBytes)

	result, err := VerifyEOA(signer, hash, signature)
	assertNoError(t, err)
	assertResult(t, result, false, MethodEOA)
}

func TestVerifyEOAMalformedSignatureDoesNotPanic(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999")
	signer := cryptoAddressForTest(privateKey)

	signature := make([]byte, 65)
	signature[64] = 0

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyEOA panicked for malformed signature: %v", r)
		}
	}()

	result, err := VerifyEOA(signer, hash, signature)
	assertNoError(t, err)
	assertResult(t, result, false, MethodEOA)
}

func TestVerifyEOADoesNotMutateSignature(t *testing.T) {
	privateKey := mustTestPrivateKey(t)
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := mustSignHash(t, hash, privateKey)
	signature[64] += 27

	original := append([]byte(nil), signature...)
	signer := cryptoAddressForTest(privateKey)

	result, err := VerifyEOA(signer, hash, signature)
	assertNoError(t, err)
	assertResult(t, result, true, MethodEOA)

	if !bytes.Equal(signature, original) {
		t.Fatalf("VerifyEOA mutated signature\nbefore: %x\nafter:  %x", original, signature)
	}
}
