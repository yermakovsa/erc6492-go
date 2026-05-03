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

func TestVerifyEIP1271ValidMagicValue(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := []byte{0x01, 0x02, 0x03}

	caller := &recordingContractCaller{
		output: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if result.Method != MethodEIP1271 {
		t.Fatalf("expected method %q, got %q", MethodEIP1271, result.Method)
	}
}

func TestVerifyEIP1271WrongMagicValue(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	hash := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	signature := []byte{0x04, 0x05, 0x06}

	caller := &recordingContractCaller{
		output: mustPackEIP1271MagicValue(t, [4]byte{0xde, 0xad, 0xbe, 0xef}),
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected invalid result")
	}

	if result.Method != MethodEIP1271 {
		t.Fatalf("expected method %q, got %q", MethodEIP1271, result.Method)
	}
}

func TestVerifyEIP1271ExecutionRevertedErrorIsCleanInvalid(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x3333333333333333333333333333333333333333")
	hash := common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	signature := []byte{0x07, 0x08, 0x09}

	caller := &recordingContractCaller{
		err: vm.ErrExecutionReverted,
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected invalid result")
	}

	if result.Method != MethodEIP1271 {
		t.Fatalf("expected method %q, got %q", MethodEIP1271, result.Method)
	}
}

func TestVerifyEIP1271ExecutionRevertedMessageIsCleanInvalid(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x4444444444444444444444444444444444444444")
	hash := common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	signature := []byte{0x0a, 0x0b, 0x0c}

	caller := &recordingContractCaller{
		err: errors.New("eth_call failed: execution reverted"),
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if result.Valid {
		t.Fatalf("expected invalid result")
	}

	if result.Method != MethodEIP1271 {
		t.Fatalf("expected method %q, got %q", MethodEIP1271, result.Method)
	}
}

func TestVerifyEIP1271NonRevertCallErrorIsReturned(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x5555555555555555555555555555555555555555")
	hash := common.HexToHash("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	signature := []byte{0x0d, 0x0e, 0x0f}

	wantErr := errors.New("rpc unavailable")
	caller := &recordingContractCaller{
		err: wantErr,
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if !errors.Is(err, wantErr) {
		t.Fatalf("VerifyEIP1271 error = %v, want %v", err, wantErr)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}
}

func TestVerifyEIP1271MalformedReturnData(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x6666666666666666666666666666666666666666")
	hash := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	signature := []byte{0x10, 0x11, 0x12}

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
			output: []byte{0x16, 0x26, 0xba, 0x7e},
		},
		{
			name:   "non abi data",
			output: []byte("not abi encoded"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := &recordingContractCaller{
				output: tt.output,
			}

			result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
			if !errors.Is(err, ErrInvalidABIOutput) {
				t.Fatalf("VerifyEIP1271 error = %v, want ErrInvalidABIOutput", err)
			}

			if result != (Result{}) {
				t.Fatalf("expected zero result on error, got %+v", result)
			}
		})
	}
}

func TestVerifyEIP1271NilCaller(t *testing.T) {
	result, err := VerifyEIP1271(
		context.Background(),
		nil,
		common.HexToAddress("0x7777777777777777777777777777777777777777"),
		common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234"),
		[]byte{0x01},
	)

	if !errors.Is(err, ErrNilCaller) {
		t.Fatalf("VerifyEIP1271 error = %v, want ErrNilCaller", err)
	}

	if result != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", result)
	}
}

func TestVerifyEIP1271CallMessage(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x8888888888888888888888888888888888888888")
	hash := common.HexToHash("0xabababababababababababababababababababababababababababababababab")
	signature := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	caller := &recordingContractCaller{
		output: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	result, err := VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected valid result")
	}

	if caller.calls != 1 {
		t.Fatalf("expected 1 call, got %d", caller.calls)
	}

	if caller.call.To == nil {
		t.Fatalf("expected call To to be set")
	}

	if *caller.call.To != signer {
		t.Fatalf("call To = %s, want %s", caller.call.To.Hex(), signer.Hex())
	}

	if len(caller.call.Data) < 4 {
		t.Fatalf("call data too short: %d bytes", len(caller.call.Data))
	}

	if !bytes.Equal(caller.call.Data[:4], eip1271IsValidSignatureSelector[:]) {
		t.Fatalf("selector = %x, want %x", caller.call.Data[:4], eip1271IsValidSignatureSelector)
	}

	decodedHash, decodedSignature := mustUnpackEIP1271CallArgs(t, caller.call.Data[4:])

	if decodedHash != hash {
		t.Fatalf("decoded hash = %s, want %s", decodedHash.Hex(), hash.Hex())
	}

	if !bytes.Equal(decodedSignature, signature) {
		t.Fatalf("decoded signature = %x, want %x", decodedSignature, signature)
	}

	if caller.blockNumber != nil {
		t.Fatalf("expected nil block number, got %v", caller.blockNumber)
	}

	if caller.call.From != (common.Address{}) {
		t.Fatalf("expected zero From address, got %s", caller.call.From.Hex())
	}
}

func TestVerifyEIP1271WithBlockNumberCopiesInput(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0x9999999999999999999999999999999999999999")
	hash := common.HexToHash("0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	signature := []byte{0x01, 0x02}

	blockNumber := big.NewInt(123)
	opt := WithBlockNumber(blockNumber)
	blockNumber.SetInt64(456)

	caller := &recordingContractCaller{
		output: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	_, err := VerifyEIP1271(ctx, caller, signer, hash, signature, opt)
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if caller.blockNumber == nil {
		t.Fatalf("expected block number to be passed")
	}

	if caller.blockNumber.Cmp(big.NewInt(123)) != 0 {
		t.Fatalf("block number = %v, want 123", caller.blockNumber)
	}
}

func TestVerifyEIP1271WithFrom(t *testing.T) {
	ctx := context.Background()
	signer := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	from := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	hash := common.HexToHash("0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")
	signature := []byte{0x03, 0x04}

	caller := &recordingContractCaller{
		output: mustPackEIP1271MagicValue(t, eip1271MagicValue),
	}

	_, err := VerifyEIP1271(ctx, caller, signer, hash, signature, WithFrom(from))
	if err != nil {
		t.Fatalf("VerifyEIP1271 returned error: %v", err)
	}

	if caller.call.From != from {
		t.Fatalf("call From = %s, want %s", caller.call.From.Hex(), from.Hex())
	}
}

type recordingContractCaller struct {
	output []byte
	err    error

	calls       int
	call        ethereum.CallMsg
	blockNumber *big.Int
}

func (c *recordingContractCaller) CallContract(
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
