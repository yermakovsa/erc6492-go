package erc6492

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

func erc6492WrapperArguments() (abi.Arguments, error) {
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}

	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	return abi.Arguments{
		{Type: addressType},
		{Type: bytesType},
		{Type: bytesType},
	}, nil
}

func encodeERC6492Wrapper(
	factory common.Address,
	factoryData []byte,
	signature []byte,
) ([]byte, error) {
	args, err := erc6492WrapperArguments()
	if err != nil {
		return nil, err
	}

	return args.Pack(
		factory,
		append([]byte(nil), factoryData...),
		append([]byte(nil), signature...),
	)
}

func decodeERC6492Wrapper(payload []byte) (WrappedSignature, error) {
	args, err := erc6492WrapperArguments()
	if err != nil {
		return WrappedSignature{}, err
	}

	values, err := args.Unpack(payload)
	if err != nil {
		return WrappedSignature{}, err
	}

	if len(values) != 3 {
		return WrappedSignature{}, fmt.Errorf("%w: expected 3 values, got %d", ErrInvalidABIOutput, len(values))
	}

	factory, ok := values[0].(common.Address)
	if !ok {
		return WrappedSignature{}, fmt.Errorf("%w: factory has type %T", ErrInvalidABIOutput, values[0])
	}

	factoryData, ok := values[1].([]byte)
	if !ok {
		return WrappedSignature{}, fmt.Errorf("%w: factoryData has type %T", ErrInvalidABIOutput, values[1])
	}

	innerSignature, ok := values[2].([]byte)
	if !ok {
		return WrappedSignature{}, fmt.Errorf("%w: signature has type %T", ErrInvalidABIOutput, values[2])
	}

	return WrappedSignature{
		Factory:     factory,
		FactoryData: append([]byte(nil), factoryData...),
		Signature:   append([]byte(nil), innerSignature...),
	}, nil
}
