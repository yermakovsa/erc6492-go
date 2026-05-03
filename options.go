package erc6492

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// VerifyOption configures signature verification.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	blockNumber *big.Int

	erc6492VerifierAddress    common.Address
	hasERC6492VerifierAddress bool

	erc6492Factory     common.Address
	erc6492FactoryData []byte
	hasERC6492Factory  bool

	from    common.Address
	hasFrom bool
}

func applyVerifyOptions(opts []VerifyOption) verifyOptions {
	var cfg verifyOptions

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return cfg
}

func copyBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}

	return new(big.Int).Set(value)
}

// WithBlockNumber verifies against a specific block number.
//
// The provided block number is copied.
func WithBlockNumber(blockNumber *big.Int) VerifyOption {
	copiedBlockNumber := copyBigInt(blockNumber)
	return func(cfg *verifyOptions) {
		if blockNumber == nil {
			cfg.blockNumber = nil
			return
		}

		cfg.blockNumber = copyBigInt(copiedBlockNumber)
	}
}

// WithERC6492VerifierAddress configures a deployed ERC-6492 verifier contract.
func WithERC6492VerifierAddress(address common.Address) VerifyOption {
	return func(cfg *verifyOptions) {
		cfg.erc6492VerifierAddress = address
		cfg.hasERC6492VerifierAddress = true
	}
}

// WithERC6492Factory provides factory information for an unwrapped
// counterfactual signature before calling the configured ERC-6492 verifier.
//
// The provided factory data is copied.
func WithERC6492Factory(factory common.Address, factoryData []byte) VerifyOption {
	return func(cfg *verifyOptions) {
		cfg.erc6492Factory = factory
		cfg.erc6492FactoryData = append([]byte(nil), factoryData...)
		cfg.hasERC6492Factory = true
	}
}

// WithFrom configures the optional eth_call sender address.
//
// This is only used for contract calls where a non-zero From field is useful.
func WithFrom(from common.Address) VerifyOption {
	return func(cfg *verifyOptions) {
		cfg.from = from
		cfg.hasFrom = true
	}
}
