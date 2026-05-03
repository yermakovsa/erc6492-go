# erc6492-go

`erc6492-go` verifies Ethereum signatures against caller-supplied `common.Hash` values.

It answers: did this Ethereum address sign this already-computed hash?

It supports:

- EOAs,
- deployed smart contract wallets via EIP-1271,
- ERC-6492 wrapped counterfactual-wallet signatures through a configured deployed verifier.

The package does not construct messages or hashes, manage RPC clients, send transactions, or include deployless verifier bytecode.

## Status

Pre-release. The API may change before the first tag.

Pin a commit if you use this before a release:

```bash
go get github.com/yermakovsa/erc6492-go@<commit>
```

After a tagged release is available:

```bash
go get github.com/yermakovsa/erc6492-go@v0.1.0
```

## API shape

The main entry points are:

- `Verify` for universal EOA / EIP-1271 / ERC-6492 routing,
- `VerifyEOA` for local EOA recovery,
- `VerifyEIP1271` for deployed contract-wallet verification,
- `VerifyERC6492` for ERC-6492 verification through a configured verifier.

`Verify` requires a caller that implements both contract calls and code reads. A standard go-ethereum `ethclient.Client` satisfies the required interfaces.

`VerifyEIP1271` and `VerifyERC6492` require only contract-call support.

## Verification order

Universal verification follows this order:

```text
ERC-6492 wrapped signature
→ WithERC6492Factory wrapping path
→ EIP-1271 if signer has code
→ EOA fallback
```

If EIP-1271 returns a clean invalid result, such as a wrong magic value or contract revert, `Verify` falls back to EOA recovery. RPC failures, ABI failures, malformed ABI-backed inputs, and unexpected verifier outputs are returned as errors.

When the ERC-6492 path is selected, the verifier result is final. A verifier `false` result returns `Result{Valid:false, Method:MethodERC6492}, nil` and does not fall through to EIP-1271 or EOA.

Call the narrower function when you need a narrower policy:

- `VerifyEOA` for EOA-only verification,
- `VerifyEIP1271` for strict deployed contract-wallet verification,
- `VerifyERC6492` for ERC-6492 verification through a configured verifier.

## Error model

```text
invalid signature → Result{Valid:false, Method:...}, nil
malformed ABI input or output / RPC failure / unexpected verifier result → error
```

Examples:

```text
wrong EOA signer                    → Result{false, MethodEOA}, nil
malformed EOA signature             → Result{false, MethodEOA}, nil
EIP-1271 wrong magic value          → Result{false, MethodEIP1271}, nil
EIP-1271 contract revert            → Result{false, MethodEIP1271}, nil
ERC-6492 verifier returns false     → Result{false, MethodERC6492}, nil
bad ERC-6492 wrapper                → error
ERC-6492 verifier call failure      → error
RPC timeout                         → error
```

## Verification details

### EOA

`VerifyEOA` verifies a 65-byte Ethereum EOA signature against the supplied hash.

It accepts `v` as `27/28` or `0/1`, normalizes it for go-ethereum recovery, enforces low-`s`, and compares the recovered address to the expected signer.

Malformed or non-canonical EOA signatures return `Result{Valid:false, Method:MethodEOA}, nil`.

### EIP-1271

`VerifyEIP1271` calls:

```solidity
isValidSignature(bytes32,bytes)
```

The decoded `bytes4` return value must equal `0x1626ba7e`.

Wrong magic values and contract reverts are clean invalid results. RPC failures, ABI failures, and malformed return data are errors.

### ERC-6492

ERC-6492 wrapped signatures end with:

```text
0x6492649264926492649264926492649264926492649264926492649264926492
```

The payload before the suffix ABI-decodes as:

```solidity
(address factory, bytes factoryData, bytes signature)
```

`VerifyERC6492` supports already-wrapped signatures and unwrapped signatures with `WithERC6492Factory`. Both paths require `WithERC6492VerifierAddress`.

Deployless verification is not implemented. If no deployed verifier address is configured, `VerifyERC6492` returns `ErrDeploylessVerifierMissing`.

The package does not implement ERC-6492 prepare-call retry logic. Any deployment or prepare semantics depend on the configured verifier contract.

## Basic usage

### Universal verification

```go
result, err := erc6492.Verify(
	ctx,
	client,
	signer,
	hash,
	signature,
	erc6492.WithERC6492VerifierAddress(verifier),
)
if err != nil {
	return err
}

if result.Valid {
	// signature is valid
}
```

`WithERC6492VerifierAddress` is only required when ERC-6492 verification may be used. Plain EOA and direct EIP-1271 verification do not require it.

### EOA-only verification

```go
result, err := erc6492.VerifyEOA(signer, hash, signature)
if err != nil {
	return err
}

if result.Valid {
	// EOA signature is valid
}
```

### ERC-6492 with factory data

```go
result, err := erc6492.VerifyERC6492(
	ctx,
	client,
	signer,
	hash,
	signature,
	erc6492.WithERC6492Factory(factory, factoryData),
	erc6492.WithERC6492VerifierAddress(verifier),
)
if err != nil {
	return err
}

if result.Valid {
	// ERC-6492 signature is valid
}
```

## Testing

```bash
go test ./...
go vet ./...
```

## Compatibility

The module currently targets Go 1.24.

## Documentation

- [Non-goals](docs/non-goals.md)
- [Security notes](docs/security.md)
- [ERC-6492 verifier bytecode](docs/verifier-bytecode.md)

## License

See [`LICENSE`](LICENSE).