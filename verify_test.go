package erc6492

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

func TestVerifyNilCaller(t *testing.T) {
	result, err := Verify(
		context.Background(),
		nil,
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte{0x01},
	)

	if !errors.Is(err, ErrNilCaller) {
		t.Fatalf("Verify error = %v, want ErrNilCaller", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}
}

func TestVerifyWrappedERC6492RoutesBeforeCodeAt(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	hash := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	verifier := common.HexToAddress("0x3333333333333333333333333333333333333333")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0x4444444444444444444444444444444444444444"),
		[]byte{0x01, 0x02},
		[]byte{0x03, 0x04},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingUniversalCaller{
		codeErr:    errors.New("CodeAt should not be called"),
		callOutput: mustPackERC6492VerifierBool(t, true),
	}

	result, err := Verify(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodERC6492 {
		t.Fatalf("expected method %q, got %q", MethodERC6492, result.Method)
	}

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", caller.callCalls)
	}

	if caller.call.To == nil || *caller.call.To != verifier {
		t.Fatalf("call To = %v, want verifier %s", caller.call.To, verifier.Hex())
	}
}

func TestVerifyWithERC6492FactoryRoutesBeforeCodeAt(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x5555555555555555555555555555555555555555")
	hash := common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	verifier := common.HexToAddress("0x6666666666666666666666666666666666666666")
	factory := common.HexToAddress("0x7777777777777777777777777777777777777777")
	factoryData := []byte{0xaa, 0xbb}
	signature := []byte{0xcc, 0xdd}

	caller := &recordingUniversalCaller{
		codeErr:    errors.New("CodeAt should not be called"),
		callOutput: mustPackERC6492VerifierBool(t, true),
	}

	result, err := Verify(
		ctx,
		caller,
		signer,
		hash,
		signature,
		WithERC6492Factory(factory, factoryData),
		WithERC6492VerifierAddress(verifier),
	)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodERC6492 {
		t.Fatalf("expected method %q, got %q", MethodERC6492, result.Method)
	}

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", caller.callCalls)
	}

	_, _, verifierSignature := mustUnpackERC6492VerifierCallArgs(t, caller.call.Data[4:])
	decoded, err := UnwrapERC6492(verifierSignature)
	if err != nil {
		t.Fatalf("UnwrapERC6492 returned error: %v", err)
	}

	if decoded.Factory != factory {
		t.Fatalf("wrapped factory = %s, want %s", decoded.Factory.Hex(), factory.Hex())
	}

	if string(decoded.FactoryData) != string(factoryData) {
		t.Fatalf("wrapped factory data = %x, want %x", decoded.FactoryData, factoryData)
	}

	if string(decoded.Signature) != string(signature) {
		t.Fatalf("wrapped signature = %x, want %x", decoded.Signature, signature)
	}
}

func TestVerifyWithERC6492FactoryAndAlreadyWrappedSignatureDoesNotDoubleWrap(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x1414141414141414141414141414141414141414")
	hash := common.HexToHash("0x1515151515151515151515151515151515151515151515151515151515151515")
	verifier := common.HexToAddress("0x1616161616161616161616161616161616161616")

	originalFactory := common.HexToAddress("0x1717171717171717171717171717171717171717")
	originalFactoryData := []byte{0x01, 0x02, 0x03}
	innerSignature := []byte{0x04, 0x05, 0x06}

	wrapped, err := WrapERC6492(originalFactory, originalFactoryData, innerSignature)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	unusedFactory := common.HexToAddress("0x1818181818181818181818181818181818181818")
	unusedFactoryData := []byte{0xaa, 0xbb, 0xcc}

	caller := &recordingUniversalCaller{
		codeErr:    errors.New("CodeAt should not be called"),
		callOutput: mustPackERC6492VerifierBool(t, true),
	}

	result, err := Verify(
		ctx,
		caller,
		signer,
		hash,
		wrapped,
		WithERC6492Factory(unusedFactory, unusedFactoryData),
		WithERC6492VerifierAddress(verifier),
	)
	assertNoError(t, err)
	assertResult(t, result, true, MethodERC6492)

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", caller.callCalls)
	}

	_, _, verifierSignature := mustUnpackERC6492VerifierCallArgs(t, caller.call.Data[4:])
	if !bytes.Equal(verifierSignature, wrapped) {
		t.Fatalf("verifier received signature = %x, want original wrapped signature %x", verifierSignature, wrapped)
	}

	decoded, err := UnwrapERC6492(verifierSignature)
	if err != nil {
		t.Fatalf("UnwrapERC6492 returned error: %v", err)
	}

	if decoded.Factory != originalFactory {
		t.Fatalf("wrapped factory = %s, want original factory %s", decoded.Factory.Hex(), originalFactory.Hex())
	}

	if !bytes.Equal(decoded.FactoryData, originalFactoryData) {
		t.Fatalf("wrapped factory data = %x, want original factory data %x", decoded.FactoryData, originalFactoryData)
	}

	if !bytes.Equal(decoded.Signature, innerSignature) {
		t.Fatalf("wrapped inner signature = %x, want original inner signature %x", decoded.Signature, innerSignature)
	}
}

func TestVerifyERC6492VerifierFalseIsFinal(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x7777777777777777777777777777777777777777")
	hash := common.HexToHash("0x7878787878787878787878787878787878787878787878787878787878787878")
	verifier := common.HexToAddress("0x8888888888888888888888888888888888888888")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
		[]byte{0x01, 0x02},
		[]byte{0x03, 0x04},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingUniversalCaller{
		codeErr:    errors.New("CodeAt should not be called"),
		callOutput: mustPackERC6492VerifierBool(t, false),
	}

	result, err := Verify(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	assertNoError(t, err)
	assertResult(t, result, false, MethodERC6492)

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", caller.callCalls)
	}
}

func TestVerifyMalformedWrappedERC6492ErrorsBeforeCodeAt(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	hash := common.HexToHash("0xabababababababababababababababababababababababababababababababab")
	malformed := append([]byte("not valid abi"), erc6492MagicSuffix[:]...)

	caller := &recordingUniversalCaller{
		codeErr: errors.New("CodeAt should not be called"),
	}

	result, err := Verify(ctx, caller, signer, hash, malformed)
	assertErrorIs(t, err, ErrMalformedERC6492Signature)
	assertZeroResult(t, result)

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.callCalls)
	}
}

func TestVerifySuffixOnlyERC6492SignatureErrorsBeforeCodeAt(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x1919191919191919191919191919191919191919")
	hash := common.HexToHash("0x2020202020202020202020202020202020202020202020202020202020202020")
	signature := append([]byte(nil), erc6492MagicSuffix[:]...)

	caller := &recordingUniversalCaller{
		codeErr: errors.New("CodeAt should not be called"),
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	assertErrorIs(t, err, ErrMalformedERC6492Signature)
	assertZeroResult(t, result)

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.callCalls)
	}
}

func TestVerifyWithERC6492FactoryMissingVerifierErrorsBeforeCodeAt(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	hash := common.HexToHash("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	factory := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	factoryData := []byte{0x01, 0x02}
	signature := []byte{0x03, 0x04}

	caller := &recordingUniversalCaller{
		codeErr: errors.New("CodeAt should not be called"),
	}

	result, err := Verify(
		ctx,
		caller,
		signer,
		hash,
		signature,
		WithERC6492Factory(factory, factoryData),
	)
	assertErrorIs(t, err, ErrDeploylessVerifierMissing)
	assertZeroResult(t, result)

	if caller.codeCalls != 0 {
		t.Fatalf("expected CodeAt not to be called, got %d calls", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.callCalls)
	}
}

func TestVerifyCodeAtErrorIsReturned(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x8888888888888888888888888888888888888888")
	hash := common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	signature := []byte{0x01}

	wantErr := errors.New("code lookup failed")
	caller := &recordingUniversalCaller{
		codeErr: wantErr,
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Verify error = %v, want %v", err, wantErr)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected no contract calls, got %d", caller.callCalls)
	}
}

func TestVerifyCodeExistsAndEIP1271RevertFallsBackToEOAValid(t *testing.T) {
	// EIP-1271 reverts are clean invalid, so Verify falls back to EOA.
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0x4545454545454545454545454545454545454545454545454545454545454545")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code:    []byte{0x60, 0x00},
		callErr: vm.ErrExecutionReverted,
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	assertNoError(t, err)
	assertResult(t, result, true, MethodEOA)

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}
}

func TestVerifyNoCodeFallsBackToEOAValid(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code: nil,
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodEOA {
		t.Fatalf("expected method %q, got %q", MethodEOA, result.Method)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected no contract calls, got %d", caller.callCalls)
	}
}

func TestVerifyNoCodeFallsBackToEOAInvalid(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	otherPrivateKey := mustOtherTestPrivateKey(t)

	signer := cryptoAddressForTest(otherPrivateKey)
	hash := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code: []byte{},
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected invalid result")
	}

	if result.Method != MethodEOA {
		t.Fatalf("expected method %q, got %q", MethodEOA, result.Method)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 0 {
		t.Fatalf("expected no contract calls, got %d", caller.callCalls)
	}
}

func TestVerifyCodeExistsAndEIP1271Valid(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x9999999999999999999999999999999999999999")
	hash := common.HexToHash("0x1212121212121212121212121212121212121212121212121212121212121212")
	signature := []byte{0x01, 0x02, 0x03}

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodEIP1271 {
		t.Fatalf("expected method %q, got %q", MethodEIP1271, result.Method)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}

	if caller.call.To == nil || *caller.call.To != signer {
		t.Fatalf("call To = %v, want signer %s", caller.call.To, signer.Hex())
	}
}

func TestVerifyCodeExistsAndEIP1271CleanInvalidFallsBackToEOAValid(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0x3434343434343434343434343434343434343434343434343434343434343434")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: mustPackEIP1271MagicValue(t, [4]byte{0xde, 0xad, 0xbe, 0xef}),
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected fallback EOA result to be valid")
	}

	if result.Method != MethodEOA {
		t.Fatalf("expected method %q, got %q", MethodEOA, result.Method)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}
}

func TestVerifyCodeExistsAndEIP1271CleanInvalidFallsBackToEOAInvalid(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	otherPrivateKey := mustOtherTestPrivateKey(t)

	signer := cryptoAddressForTest(otherPrivateKey)
	hash := common.HexToHash("0x5656565656565656565656565656565656565656565656565656565656565656")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: mustPackEIP1271MagicValue(t, [4]byte{0xde, 0xad, 0xbe, 0xef}),
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected fallback EOA result to be invalid")
	}

	if result.Method != MethodEOA {
		t.Fatalf("expected method %q, got %q", MethodEOA, result.Method)
	}

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}
}

func TestVerifyCodeExistsAndEIP1271NonRevertCallErrorDoesNotFallBackToEOA(t *testing.T) {
	// Non-revert RPC errors must not fall back to EOA.
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0x6767676767676767676767676767676767676767676767676767676767676767")
	signature := mustSignHash(t, hash, privateKey)
	wantErr := errors.New("rpc unavailable")

	caller := &recordingUniversalCaller{
		code:    []byte{0x60, 0x00},
		callErr: wantErr,
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Verify error = %v, want %v", err, wantErr)
	}
	assertZeroResult(t, result)

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}
}

func TestVerifyCodeExistsAndEIP1271ErrorDoesNotFallBackToEOA(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0x7878787878787878787878787878787878787878787878787878787878787878")
	signature := mustSignHash(t, hash, privateKey)

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: []byte("not abi encoded"),
	}

	result, err := Verify(ctx, caller, signer, hash, signature)
	assertErrorIs(t, err, ErrInvalidABIOutput)
	assertZeroResult(t, result)

	if caller.codeCalls != 1 {
		t.Fatalf("expected 1 CodeAt call, got %d", caller.codeCalls)
	}

	if caller.callCalls != 1 {
		t.Fatalf("expected 1 EIP-1271 call, got %d", caller.callCalls)
	}
}

func TestVerifyWithBlockNumberCopiesInputAndPassesToCodeAt(t *testing.T) {
	ctx := context.Background()
	privateKey := mustTestPrivateKey(t)
	signer := cryptoAddressForTest(privateKey)
	hash := common.HexToHash("0x9090909090909090909090909090909090909090909090909090909090909090")
	signature := mustSignHash(t, hash, privateKey)

	blockNumber := big.NewInt(123)
	opt := WithBlockNumber(blockNumber)
	blockNumber.SetInt64(456)

	caller := &recordingUniversalCaller{
		code: nil,
	}

	result, err := Verify(ctx, caller, signer, hash, signature, opt)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid EOA result")
	}

	if caller.codeBlockNumber == nil {
		t.Fatalf("expected CodeAt block number to be passed")
	}

	if caller.codeBlockNumber.Cmp(big.NewInt(123)) != 0 {
		t.Fatalf("CodeAt block number = %v, want 123", caller.codeBlockNumber)
	}
}

func TestVerifyWithBlockNumberPassesToEIP1271Call(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	hash := common.HexToHash("0xabababababababababababababababababababababababababababababababab")
	signature := []byte{0x01, 0x02}
	blockNumber := big.NewInt(789)

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	result, err := Verify(ctx, caller, signer, hash, signature, WithBlockNumber(blockNumber))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid EIP-1271 result")
	}

	if caller.codeBlockNumber == nil {
		t.Fatalf("expected CodeAt block number to be passed")
	}

	if caller.codeBlockNumber.Cmp(big.NewInt(789)) != 0 {
		t.Fatalf("CodeAt block number = %v, want 789", caller.codeBlockNumber)
	}

	if caller.callBlockNumber == nil {
		t.Fatalf("expected CallContract block number to be passed")
	}

	if caller.callBlockNumber.Cmp(big.NewInt(789)) != 0 {
		t.Fatalf("CallContract block number = %v, want 789", caller.callBlockNumber)
	}
}

func TestVerifyWithFromPassesToEIP1271Call(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	from := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	hash := common.HexToHash("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	signature := []byte{0x03, 0x04}

	caller := &recordingUniversalCaller{
		code:       []byte{0x60, 0x00},
		callOutput: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	result, err := Verify(ctx, caller, signer, hash, signature, WithFrom(from))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid EIP-1271 result")
	}

	if caller.call.From != from {
		t.Fatalf("call From = %s, want %s", caller.call.From.Hex(), from.Hex())
	}
}

type recordingUniversalCaller struct {
	code    []byte
	codeErr error

	callOutput []byte
	callErr    error

	codeCalls int
	callCalls int

	codeContract    common.Address
	codeBlockNumber *big.Int

	call            ethereum.CallMsg
	callBlockNumber *big.Int
}

func (c *recordingUniversalCaller) CodeAt(
	ctx context.Context,
	contract common.Address,
	blockNumber *big.Int,
) ([]byte, error) {
	c.codeCalls++
	c.codeContract = contract
	c.codeBlockNumber = copyBigInt(blockNumber)

	if c.codeErr != nil {
		return nil, c.codeErr
	}

	return append([]byte(nil), c.code...), nil
}

func (c *recordingUniversalCaller) CallContract(
	ctx context.Context,
	call ethereum.CallMsg,
	blockNumber *big.Int,
) ([]byte, error) {
	c.callCalls++
	c.call = copyCallMsgForTest(call)
	c.callBlockNumber = copyBigInt(blockNumber)

	if c.callErr != nil {
		return nil, c.callErr
	}

	return append([]byte(nil), c.callOutput...), nil
}
