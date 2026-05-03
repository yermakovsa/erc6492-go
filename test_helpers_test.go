package erc6492

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func mustTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe5129617082799c5c0ebca65f4a2f8a")
	if err != nil {
		t.Fatalf("failed to create test private key: %v", err)
	}

	return privateKey
}

func mustOtherTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := crypto.HexToECDSA("8f2a559490b2b9fdb11a9e06fd95b68a17b5f14f5f13ed651e3db33b507f9f9d")
	if err != nil {
		t.Fatalf("failed to create other test private key: %v", err)
	}

	return privateKey
}

func mustSignHash(t *testing.T, hash common.Hash, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}

	return signature
}

func cryptoAddressForTest(privateKey *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}

func mustPackEIP1271MagicValue(t *testing.T, magic [4]byte) []byte {
	t.Helper()

	bytes4Type, err := abi.NewType("bytes4", "", nil)
	if err != nil {
		t.Fatalf("failed to create bytes4 ABI type: %v", err)
	}

	args := abi.Arguments{
		{Type: bytes4Type},
	}

	output, err := args.Pack(magic)
	if err != nil {
		t.Fatalf("failed to pack EIP-1271 magic value: %v", err)
	}

	return output
}

func mustUnpackEIP1271CallArgs(t *testing.T, data []byte) (common.Hash, []byte) {
	t.Helper()

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		t.Fatalf("failed to create bytes32 ABI type: %v", err)
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		t.Fatalf("failed to create bytes ABI type: %v", err)
	}

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytesType},
	}

	values, err := args.Unpack(data)
	if err != nil {
		t.Fatalf("failed to unpack EIP-1271 call args: %v", err)
	}

	if len(values) != 2 {
		t.Fatalf("decoded %d values, want 2", len(values))
	}

	hashBytes, ok := values[0].([32]byte)
	if !ok {
		t.Fatalf("decoded hash has type %T, want [32]byte", values[0])
	}

	signature, ok := values[1].([]byte)
	if !ok {
		t.Fatalf("decoded signature has type %T, want []byte", values[1])
	}

	return common.BytesToHash(hashBytes[:]), signature
}

func mustPackERC6492VerifierBool(t *testing.T, valid bool) []byte {
	t.Helper()

	boolType, err := abi.NewType("bool", "", nil)
	if err != nil {
		t.Fatalf("failed to create bool ABI type: %v", err)
	}

	args := abi.Arguments{
		{Type: boolType},
	}

	output, err := args.Pack(valid)
	if err != nil {
		t.Fatalf("failed to pack ERC-6492 verifier bool: %v", err)
	}

	return output
}

func mustUnpackERC6492VerifierCallArgs(t *testing.T, data []byte) (common.Address, common.Hash, []byte) {
	t.Helper()

	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		t.Fatalf("failed to create address ABI type: %v", err)
	}

	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		t.Fatalf("failed to create bytes32 ABI type: %v", err)
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		t.Fatalf("failed to create bytes ABI type: %v", err)
	}

	args := abi.Arguments{
		{Type: addressType},
		{Type: bytes32Type},
		{Type: bytesType},
	}

	values, err := args.Unpack(data)
	if err != nil {
		t.Fatalf("failed to unpack ERC-6492 verifier call args: %v", err)
	}

	if len(values) != 3 {
		t.Fatalf("decoded %d values, want 3", len(values))
	}

	signer, ok := values[0].(common.Address)
	if !ok {
		t.Fatalf("decoded signer has type %T, want common.Address", values[0])
	}

	hashBytes, ok := values[1].([32]byte)
	if !ok {
		t.Fatalf("decoded hash has type %T, want [32]byte", values[1])
	}

	signature, ok := values[2].([]byte)
	if !ok {
		t.Fatalf("decoded signature has type %T, want []byte", values[2])
	}

	return signer, common.BytesToHash(hashBytes[:]), signature
}

func copyCallMsgForTest(call ethereum.CallMsg) ethereum.CallMsg {
	copied := call

	if call.To != nil {
		to := *call.To
		copied.To = &to
	}

	copied.Data = append([]byte(nil), call.Data...)
	copied.AccessList = append(copied.AccessList[:0:0], call.AccessList...)

	return copied
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertErrorIs(t *testing.T, err error, target error) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

func assertResult(t *testing.T, got Result, wantValid bool, wantMethod Method) {
	t.Helper()

	if got.Valid != wantValid {
		t.Fatalf("valid = %v, want %v", got.Valid, wantValid)
	}

	if got.Method != wantMethod {
		t.Fatalf("method = %q, want %q", got.Method, wantMethod)
	}
}

func assertZeroResult(t *testing.T, got Result) {
	t.Helper()

	if got != (Result{}) {
		t.Fatalf("expected zero result on error, got %+v", got)
	}
}
