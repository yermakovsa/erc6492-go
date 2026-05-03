package erc6492_test

import (
	"context"
	"fmt"
	"math/big"

	erc6492 "github.com/yermakovsa/erc6492-go"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type exampleCaller struct {
	code   []byte
	output []byte
}

func (c exampleCaller) CallContract(
	ctx context.Context,
	call ethereum.CallMsg,
	blockNumber *big.Int,
) ([]byte, error) {
	return append([]byte(nil), c.output...), nil
}

func (c exampleCaller) CodeAt(
	ctx context.Context,
	contract common.Address,
	blockNumber *big.Int,
) ([]byte, error) {
	return append([]byte(nil), c.code...), nil
}

func ExampleVerify() {
	ctx := context.Background()

	caller := exampleCaller{
		code:   []byte{0x01},
		output: exampleEIP1271MagicReturn(),
	}

	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := []byte{0x01, 0x02, 0x03}

	result, err := erc6492.Verify(ctx, caller, signer, hash, signature)
	if err != nil {
		// Handle malformed input, RPC failure, ABI failure, or unexpected output.
		return
	}

	fmt.Println(result.Valid, result.Method)

	// Output: true eip1271
}

func ExampleVerifyEOA() {
	privateKey, err := crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe5129617082799c5c0ebca65f4a2f8a")
	if err != nil {
		return
	}

	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return
	}

	signer := crypto.PubkeyToAddress(privateKey.PublicKey)

	result, err := erc6492.VerifyEOA(signer, hash, signature)
	if err != nil {
		return
	}

	fmt.Println(result.Valid, result.Method)

	// Output: true eoa
}

func ExampleVerifyEIP1271() {
	ctx := context.Background()

	caller := exampleCaller{
		output: exampleEIP1271MagicReturn(),
	}

	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := []byte{0x01, 0x02, 0x03}

	result, err := erc6492.VerifyEIP1271(ctx, caller, signer, hash, signature)
	if err != nil {
		// Handle RPC failure, ABI failure, or malformed return data.
		return
	}

	fmt.Println(result.Valid, result.Method)

	// Output: true eip1271
}

func ExampleVerifyERC6492() {
	ctx := context.Background()

	caller := exampleCaller{
		output: exampleBoolReturn(true),
	}

	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	hash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	signature := []byte{0x01, 0x02, 0x03}

	factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
	factoryData := []byte{0xde, 0xad, 0xbe, 0xef}
	verifier := common.HexToAddress("0x3333333333333333333333333333333333333333")

	result, err := erc6492.VerifyERC6492(
		ctx,
		caller,
		signer,
		hash,
		signature,
		erc6492.WithERC6492Factory(factory, factoryData),
		erc6492.WithERC6492VerifierAddress(verifier),
	)
	if err != nil {
		// Handle malformed wrapper data, RPC failure, ABI failure,
		// missing verifier configuration, or unexpected verifier output.
		return
	}

	fmt.Println(result.Valid, result.Method)

	// Output: true erc6492
}

func exampleEIP1271MagicReturn() []byte {
	output := make([]byte, 32)
	copy(output[:4], []byte{0x16, 0x26, 0xba, 0x7e})
	return output
}

func exampleBoolReturn(value bool) []byte {
	output := make([]byte, 32)
	if value {
		output[31] = 1
	}
	return output
}
