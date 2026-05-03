package erc6492

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestIsERC6492Signature(t *testing.T) {
	validWrapped, err := WrapERC6492(
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		[]byte{0x01, 0x02, 0x03},
		[]byte{0x04, 0x05, 0x06},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	nearMiss := append([]byte(nil), validWrapped...)
	nearMiss[len(nearMiss)-1] ^= 0x01

	tests := []struct {
		name      string
		signature []byte
		want      bool
	}{
		{
			name:      "nil",
			signature: nil,
			want:      false,
		},
		{
			name:      "empty",
			signature: []byte{},
			want:      false,
		},
		{
			name:      "short",
			signature: []byte{0x64, 0x92},
			want:      false,
		},
		{
			name:      "random without suffix",
			signature: []byte("not an erc6492 signature"),
			want:      false,
		},
		{
			name:      "exact suffix only",
			signature: append([]byte(nil), erc6492MagicSuffix[:]...),
			want:      true,
		},
		{
			name:      "wrapped signature",
			signature: validWrapped,
			want:      true,
		},
		{
			name:      "near miss suffix",
			signature: nearMiss,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsERC6492Signature(tt.signature)
			if got != tt.want {
				t.Fatalf("IsERC6492Signature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsWrappedSignatureAlias(t *testing.T) {
	signatures := [][]byte{
		nil,
		{},
		[]byte("not wrapped"),
		append([]byte(nil), erc6492MagicSuffix[:]...),
	}

	for _, signature := range signatures {
		got := IsWrappedSignature(signature)
		want := IsERC6492Signature(signature)

		if got != want {
			t.Fatalf("IsWrappedSignature(%x) = %v, want %v", signature, got, want)
		}
	}
}

func TestWrapAndUnwrapERC6492RoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		factory        common.Address
		factoryData    []byte
		innerSignature []byte
	}{
		{
			name:           "non empty bytes",
			factory:        common.HexToAddress("0x2222222222222222222222222222222222222222"),
			factoryData:    []byte{0xde, 0xad, 0xbe, 0xef},
			innerSignature: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:           "empty bytes",
			factory:        common.HexToAddress("0x3333333333333333333333333333333333333333"),
			factoryData:    nil,
			innerSignature: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped, err := WrapERC6492(tt.factory, tt.factoryData, tt.innerSignature)
			assertNoError(t, err)

			if !IsERC6492Signature(wrapped) {
				t.Fatalf("expected wrapped signature to have ERC-6492 suffix")
			}

			if !bytes.HasSuffix(wrapped, erc6492MagicSuffix[:]) {
				t.Fatalf("expected wrapped signature to end with magic suffix")
			}

			decoded, err := UnwrapERC6492(wrapped)
			assertNoError(t, err)

			if decoded.Factory != tt.factory {
				t.Fatalf("decoded factory = %s, want %s", decoded.Factory.Hex(), tt.factory.Hex())
			}

			if !bytes.Equal(decoded.FactoryData, tt.factoryData) {
				t.Fatalf("decoded factory data = %x, want %x", decoded.FactoryData, tt.factoryData)
			}

			if !bytes.Equal(decoded.Signature, tt.innerSignature) {
				t.Fatalf("decoded signature = %x, want %x", decoded.Signature, tt.innerSignature)
			}
		})
	}
}

func TestWrapAndUnwrapERC6492KnownABIFixture(t *testing.T) {
	// Fixture format matches AmbireTech/viem/ox:
	//
	//	abi.encode(address, bytes, bytes) + ERC-6492 magic suffix
	//
	// Values:
	//
	//	factory     = 0x1111111111111111111111111111111111111111
	//	factoryData = 0xdeadbeef
	//	signature   = 0xbeef
	factory := common.HexToAddress("0x1111111111111111111111111111111111111111")
	factoryData := []byte{0xde, 0xad, 0xbe, 0xef}
	innerSignature := []byte{0xbe, 0xef}

	want := common.FromHex(
		"0x" +
			"0000000000000000000000001111111111111111111111111111111111111111" +
			"0000000000000000000000000000000000000000000000000000000000000060" +
			"00000000000000000000000000000000000000000000000000000000000000a0" +
			"0000000000000000000000000000000000000000000000000000000000000004" +
			"deadbeef00000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000002" +
			"beef000000000000000000000000000000000000000000000000000000000000" +
			"6492649264926492649264926492649264926492649264926492649264926492",
	)

	wrapped, err := WrapERC6492(factory, factoryData, innerSignature)
	assertNoError(t, err)

	if !bytes.Equal(wrapped, want) {
		t.Fatalf("wrapped fixture mismatch\n got: 0x%x\nwant: 0x%x", wrapped, want)
	}

	decoded, err := UnwrapERC6492(want)
	assertNoError(t, err)

	if decoded.Factory != factory {
		t.Fatalf("decoded factory = %s, want %s", decoded.Factory.Hex(), factory.Hex())
	}

	if !bytes.Equal(decoded.FactoryData, factoryData) {
		t.Fatalf("decoded factory data = %x, want %x", decoded.FactoryData, factoryData)
	}

	if !bytes.Equal(decoded.Signature, innerSignature) {
		t.Fatalf("decoded signature = %x, want %x", decoded.Signature, innerSignature)
	}
}

func TestUnwrapERC6492MalformedSignatures(t *testing.T) {
	tests := []struct {
		name      string
		signature []byte
	}{
		{
			name:      "missing suffix",
			signature: []byte("missing suffix"),
		},
		{
			name:      "malformed abi with suffix",
			signature: append([]byte("not valid abi"), erc6492MagicSuffix[:]...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnwrapERC6492(tt.signature)
			assertErrorIs(t, err, ErrMalformedERC6492Signature)
		})
	}
}

func TestWrapERC6492CopiesInputs(t *testing.T) {
	factory := common.HexToAddress("0x4444444444444444444444444444444444444444")
	factoryData := []byte{0x01, 0x02, 0x03}
	innerSignature := []byte{0x04, 0x05, 0x06}

	wrapped, err := WrapERC6492(factory, factoryData, innerSignature)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	factoryData[0] = 0xff
	innerSignature[0] = 0xee

	decoded, err := UnwrapERC6492(wrapped)
	if err != nil {
		t.Fatalf("UnwrapERC6492 returned error: %v", err)
	}

	if !bytes.Equal(decoded.FactoryData, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("decoded factory data = %x, want original data", decoded.FactoryData)
	}

	if !bytes.Equal(decoded.Signature, []byte{0x04, 0x05, 0x06}) {
		t.Fatalf("decoded signature = %x, want original signature", decoded.Signature)
	}
}

func TestUnwrapERC6492ReturnsIndependentSlices(t *testing.T) {
	factory := common.HexToAddress("0x5555555555555555555555555555555555555555")
	factoryData := []byte{0x10, 0x20, 0x30}
	innerSignature := []byte{0x40, 0x50, 0x60}

	wrapped, err := WrapERC6492(factory, factoryData, innerSignature)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	first, err := UnwrapERC6492(wrapped)
	if err != nil {
		t.Fatalf("first UnwrapERC6492 returned error: %v", err)
	}

	second, err := UnwrapERC6492(wrapped)
	if err != nil {
		t.Fatalf("second UnwrapERC6492 returned error: %v", err)
	}

	first.FactoryData[0] = 0xff
	first.Signature[0] = 0xee

	if !bytes.Equal(second.FactoryData, factoryData) {
		t.Fatalf("second decoded factory data = %x, want %x", second.FactoryData, factoryData)
	}

	if !bytes.Equal(second.Signature, innerSignature) {
		t.Fatalf("second decoded signature = %x, want %x", second.Signature, innerSignature)
	}
}

func TestVerifyERC6492NilCaller(t *testing.T) {
	result, err := VerifyERC6492(
		context.Background(),
		nil,
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte{0x01},
	)

	if !errors.Is(err, ErrNilCaller) {
		t.Fatalf("VerifyERC6492 error = %v, want ErrNilCaller", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}
}

func TestVerifyERC6492UnwrappedWithoutFactory(t *testing.T) {
	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(
		context.Background(),
		caller,
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		[]byte{0x01, 0x02, 0x03},
		WithERC6492VerifierAddress(common.HexToAddress("0x3333333333333333333333333333333333333333")),
	)

	if !errors.Is(err, ErrMissingERC6492Factory) {
		t.Fatalf("VerifyERC6492 error = %v, want ErrMissingERC6492Factory", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}

	if caller.calls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.calls)
	}
}

func TestVerifyERC6492MalformedWrappedSignature(t *testing.T) {
	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	malformed := append([]byte("not valid abi"), erc6492MagicSuffix[:]...)

	result, err := VerifyERC6492(
		context.Background(),
		caller,
		common.HexToAddress("0x4444444444444444444444444444444444444444"),
		common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		malformed,
		WithERC6492VerifierAddress(common.HexToAddress("0x5555555555555555555555555555555555555555")),
	)

	if !errors.Is(err, ErrMalformedERC6492Signature) {
		t.Fatalf("VerifyERC6492 error = %v, want ErrMalformedERC6492Signature", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}

	if caller.calls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.calls)
	}
}

func TestVerifyERC6492MissingVerifierAddressReturnsDeploylessGuard(t *testing.T) {
	factory := common.HexToAddress("0x6666666666666666666666666666666666666666")
	wrapped, err := WrapERC6492(factory, []byte{0x01}, []byte{0x02})
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(
		context.Background(),
		caller,
		common.HexToAddress("0x7777777777777777777777777777777777777777"),
		common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
		wrapped,
	)

	if !errors.Is(err, ErrDeploylessVerifierMissing) {
		t.Fatalf("VerifyERC6492 error = %v, want ErrDeploylessVerifierMissing", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}

	if caller.calls != 0 {
		t.Fatalf("expected verifier not to be called, got %d calls", caller.calls)
	}
}

func TestVerifyERC6492VerifierReturnsTrue(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x8888888888888888888888888888888888888888")
	hash := common.HexToHash("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	verifier := common.HexToAddress("0x9999999999999999999999999999999999999999")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte{0x01, 0x02},
		[]byte{0x03, 0x04},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodERC6492 {
		t.Fatalf("expected method %q, got %q", MethodERC6492, result.Method)
	}
}

func TestVerifyERC6492VerifierReturnsFalse(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	hash := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	verifier := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd"),
		[]byte{0x05, 0x06},
		[]byte{0x07, 0x08},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, false),
	}

	result, err := VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected invalid result")
	}

	if result.Method != MethodERC6492 {
		t.Fatalf("expected method %q, got %q", MethodERC6492, result.Method)
	}
}

func TestVerifyERC6492CallMessageForWrappedSignature(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0x1212121212121212121212121212121212121212121212121212121212121212")
	verifier := common.HexToAddress("0x2222222222222222222222222222222222222222")
	factory := common.HexToAddress("0x3333333333333333333333333333333333333333")
	factoryData := []byte{0xde, 0xad}
	innerSignature := []byte{0xbe, 0xef}

	wrapped, err := WrapERC6492(factory, factoryData, innerSignature)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if caller.calls != 1 {
		t.Fatalf("expected 1 verifier call, got %d", caller.calls)
	}

	if caller.call.To == nil {
		t.Fatalf("expected call To to be set")
	}

	if *caller.call.To != verifier {
		t.Fatalf("call To = %s, want %s", caller.call.To.Hex(), verifier.Hex())
	}

	if len(caller.call.Data) < 4 {
		t.Fatalf("call data too short: %d bytes", len(caller.call.Data))
	}

	wantSelector := erc6492VerifierSelector[:]
	if !bytes.Equal(caller.call.Data[:4], wantSelector) {
		t.Fatalf("selector = %x, want %x", caller.call.Data[:4], wantSelector)
	}

	decodedSigner, decodedHash, decodedSignature := mustUnpackERC6492VerifierCallArgs(t, caller.call.Data[4:])

	if decodedSigner != signer {
		t.Fatalf("decoded signer = %s, want %s", decodedSigner.Hex(), signer.Hex())
	}

	if decodedHash != hash {
		t.Fatalf("decoded hash = %s, want %s", decodedHash.Hex(), hash.Hex())
	}

	if !bytes.Equal(decodedSignature, wrapped) {
		t.Fatalf("decoded signature = %x, want wrapped signature %x", decodedSignature, wrapped)
	}

	if caller.blockNumber != nil {
		t.Fatalf("expected nil block number, got %v", caller.blockNumber)
	}

	if caller.call.From != (common.Address{}) {
		t.Fatalf("expected zero From address, got %s", caller.call.From.Hex())
	}
}

func TestVerifyERC6492WrapsUnwrappedSignatureWithFactory(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x4444444444444444444444444444444444444444")
	hash := common.HexToHash("0x3434343434343434343434343434343434343434343434343434343434343434")
	verifier := common.HexToAddress("0x5555555555555555555555555555555555555555")
	factory := common.HexToAddress("0x6666666666666666666666666666666666666666")
	factoryData := []byte{0x01, 0x02, 0x03}
	innerSignature := []byte{0x04, 0x05, 0x06}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(
		ctx,
		caller,
		signer,
		hash,
		innerSignature,
		WithERC6492Factory(factory, factoryData),
		WithERC6492VerifierAddress(verifier),
	)
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	decodedSigner, decodedHash, decodedSignature := mustUnpackERC6492VerifierCallArgs(t, caller.call.Data[4:])

	if decodedSigner != signer {
		t.Fatalf("decoded signer = %s, want %s", decodedSigner.Hex(), signer.Hex())
	}

	if decodedHash != hash {
		t.Fatalf("decoded hash = %s, want %s", decodedHash.Hex(), hash.Hex())
	}

	if !IsERC6492Signature(decodedSignature) {
		t.Fatalf("expected verifier signature argument to be wrapped")
	}

	decodedWrapped, err := UnwrapERC6492(decodedSignature)
	if err != nil {
		t.Fatalf("UnwrapERC6492 returned error: %v", err)
	}

	if decodedWrapped.Factory != factory {
		t.Fatalf("wrapped factory = %s, want %s", decodedWrapped.Factory.Hex(), factory.Hex())
	}

	if !bytes.Equal(decodedWrapped.FactoryData, factoryData) {
		t.Fatalf("wrapped factory data = %x, want %x", decodedWrapped.FactoryData, factoryData)
	}

	if !bytes.Equal(decodedWrapped.Signature, innerSignature) {
		t.Fatalf("wrapped inner signature = %x, want %x", decodedWrapped.Signature, innerSignature)
	}
}

func TestVerifyERC6492AlreadyWrappedSignatureWithFactoryDoesNotDoubleWrap(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x7777777777777777777777777777777777777777")
	hash := common.HexToHash("0x4545454545454545454545454545454545454545454545454545454545454545")
	verifier := common.HexToAddress("0x8888888888888888888888888888888888888888")

	originalFactory := common.HexToAddress("0x9999999999999999999999999999999999999999")
	originalFactoryData := []byte{0x01, 0x02, 0x03}
	innerSignature := []byte{0x04, 0x05, 0x06}

	wrapped, err := WrapERC6492(originalFactory, originalFactoryData, innerSignature)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	unusedFactory := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	unusedFactoryData := []byte{0xaa, 0xbb, 0xcc}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	result, err := VerifyERC6492(
		ctx,
		caller,
		signer,
		hash,
		wrapped,
		WithERC6492Factory(unusedFactory, unusedFactoryData),
		WithERC6492VerifierAddress(verifier),
	)
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	assertResult(t, result, true, MethodERC6492)

	decodedSigner, decodedHash, decodedSignature := mustUnpackERC6492VerifierCallArgs(t, caller.call.Data[4:])

	if decodedSigner != signer {
		t.Fatalf("decoded signer = %s, want %s", decodedSigner.Hex(), signer.Hex())
	}

	if decodedHash != hash {
		t.Fatalf("decoded hash = %s, want %s", decodedHash.Hex(), hash.Hex())
	}

	if !bytes.Equal(decodedSignature, wrapped) {
		t.Fatalf("verifier received signature = %x, want original wrapped signature %x", decodedSignature, wrapped)
	}

	decodedWrapped, err := UnwrapERC6492(decodedSignature)
	if err != nil {
		t.Fatalf("UnwrapERC6492 returned error: %v", err)
	}

	if decodedWrapped.Factory != originalFactory {
		t.Fatalf("wrapped factory = %s, want original factory %s", decodedWrapped.Factory.Hex(), originalFactory.Hex())
	}

	if !bytes.Equal(decodedWrapped.FactoryData, originalFactoryData) {
		t.Fatalf("wrapped factory data = %x, want original factory data %x", decodedWrapped.FactoryData, originalFactoryData)
	}

	if !bytes.Equal(decodedWrapped.Signature, innerSignature) {
		t.Fatalf("wrapped inner signature = %x, want original inner signature %x", decodedWrapped.Signature, innerSignature)
	}
}

func TestVerifyERC6492CallErrorIsReturned(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x7777777777777777777777777777777777777777")
	hash := common.HexToHash("0x5656565656565656565656565656565656565656565656565656565656565656")
	verifier := common.HexToAddress("0x8888888888888888888888888888888888888888")
	wantErr := errors.New("rpc unavailable")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
		[]byte{0x01},
		[]byte{0x02},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		err: wantErr,
	}

	result, err := VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
	if !errors.Is(err, wantErr) {
		t.Fatalf("VerifyERC6492 error = %v, want %v", err, wantErr)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}
}

func TestVerifyERC6492MalformedVerifierOutput(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	hash := common.HexToHash("0x7878787878787878787878787878787878787878787878787878787878787878")
	verifier := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
		[]byte{0x01},
		[]byte{0x02},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	tests := []struct {
		name   string
		output []byte
	}{
		{
			name:   "nil",
			output: nil,
		},
		{
			name:   "empty",
			output: []byte{},
		},
		{
			name:   "short",
			output: []byte{0x01},
		},
		{
			name:   "non abi data",
			output: []byte("not abi encoded"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &recordingERC6492Caller{
				output: tt.output,
			}

			result, err := VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier))
			if !errors.Is(err, ErrUnexpectedVerifierData) {
				t.Fatalf("VerifyERC6492 error = %v, want ErrUnexpectedVerifierData", err)
			}

			if result != (Result{}) {
				t.Fatalf("expected zero result on error, got %+v", result)
			}
		})
	}
}

func TestVerifyERC6492WithBlockNumberCopiesInput(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
	hash := common.HexToHash("0x9090909090909090909090909090909090909090909090909090909090909090")
	verifier := common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	blockNumber := big.NewInt(123)
	opt := WithBlockNumber(blockNumber)
	blockNumber.SetInt64(456)

	wrapped, err := WrapERC6492(
		common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
		[]byte{0x01},
		[]byte{0x02},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	_, err = VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier), opt)
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if caller.blockNumber == nil {
		t.Fatalf("expected block number to be passed")
	}

	if caller.blockNumber.Cmp(big.NewInt(123)) != 0 {
		t.Fatalf("block number = %v, want 123", caller.blockNumber)
	}
}

func TestVerifyERC6492WithFrom(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0xabababababababababababababababababababababababababababababababab")
	verifier := common.HexToAddress("0x2222222222222222222222222222222222222222")
	from := common.HexToAddress("0x3333333333333333333333333333333333333333")

	wrapped, err := WrapERC6492(
		common.HexToAddress("0x4444444444444444444444444444444444444444"),
		[]byte{0x01},
		[]byte{0x02},
	)
	if err != nil {
		t.Fatalf("WrapERC6492 returned error: %v", err)
	}

	caller := &recordingERC6492Caller{
		output: mustPackERC6492VerifierBool(t, true),
	}

	_, err = VerifyERC6492(ctx, caller, signer, hash, wrapped, WithERC6492VerifierAddress(verifier), WithFrom(from))
	if err != nil {
		t.Fatalf("VerifyERC6492 returned error: %v", err)
	}

	if caller.call.From != from {
		t.Fatalf("call From = %s, want %s", caller.call.From.Hex(), from.Hex())
	}
}

type recordingERC6492Caller struct {
	output []byte
	err    error

	calls       int
	call        ethereum.CallMsg
	blockNumber *big.Int
}

func (c *recordingERC6492Caller) CallContract(
	ctx context.Context,
	call ethereum.CallMsg,
	blockNumber *big.Int,
) ([]byte, error) {
	c.calls++
	c.call = copyCallMsgForTest(call)
	c.blockNumber = copyBigInt(blockNumber)

	if c.err != nil {
		return nil, c.err
	}

	return append([]byte(nil), c.output...), nil
}

func TestERC6492VerifierSelectorConstant(t *testing.T) {
	want := crypto.Keccak256([]byte("isValidSig(address,bytes32,bytes)"))[:4]

	if !bytes.Equal(erc6492VerifierSelector[:], want) {
		t.Fatalf("erc6492 verifier selector = 0x%x, want 0x%x", erc6492VerifierSelector, want)
	}
}
