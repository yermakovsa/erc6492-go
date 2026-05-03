# Security notes

`erc6492-go` verifies signatures against caller-supplied Ethereum hashes.

This document describes the current security model. The project is pre-release,
and behavior may change before the first tagged release.

## Hashing is out of scope

Callers are responsible for supplying the exact `common.Hash` that should be verified.

The package does not perform:

* EIP-191 prefixing,
* EIP-712 typed-data hashing,
* SIWE message construction,
* raw message hashing.

A valid result only proves that the address signed the supplied hash under the selected verification method. It does not prove that the hash represents the message, domain, chain, or application intent the caller had in mind.

## Verification model

Universal verification follows this order:

```text
ERC-6492 wrapped signature
→ WithERC6492Factory wrapping path
→ EIP-1271 if signer has code
→ EOA fallback
```

This behavior must be documented clearly for callers because universal signature verification is intentionally broader than strict EOA-only or contract-only verification.

Use the narrowest function that matches your security requirement:

* `VerifyEOA` for EOA-only verification.
* `VerifyEIP1271` for strict deployed contract-wallet verification.
* `VerifyERC6492` for ERC-6492 verification through a configured verifier.
* `Verify` for universal verification with the documented fallback behavior.

## Deployed-contract EOA fallback

Universal `Verify` falls back to EOA verification when all of the following are true:

1. the signer address has deployed code,
2. the signature is not handled through ERC-6492,
3. EIP-1271 returns a clean invalid result, such as a wrong magic value or contract revert.

This fallback is part of the universal verification model. It should not be confused with a strict contract-wallet-only policy.

The fallback is not used for RPC failures, ABI failures, malformed ABI-backed input, or unexpected verifier output. Those cases return errors.

When the ERC-6492 path is selected, the deployed verifier result is final. A clean verifier `false` result returns `Result{Valid:false, Method:MethodERC6492}, nil` and does not fall through to EIP-1271 or EOA.

## Error model

The error model is:

```text
invalid signature → Result{Valid:false, Method:...}, nil
malformed ABI-backed input / ABI failure / RPC failure / unexpected verifier result → error
```

Malformed or non-canonical EOA signatures are treated as invalid signatures.

Malformed ERC-6492 wrappers, malformed ABI return data, and unexpected verifier output are errors.
`Valid:false` means verification completed and rejected the signature. A non-nil error means verification did not complete cleanly. 

## EOA malleability

EOA verification enforces low-`s` signatures through go-ethereum signature validation.

The verifier accepts `v` as either:

```text
27/28
0/1
```

and normalizes it for public-key recovery.

Bad length, bad `v`, high-`s`, and recovery failure are treated as invalid signatures, not operational errors or panics.

## EIP-1271 contract behavior

EIP-1271 verification calls:

```solidity
isValidSignature(bytes32,bytes)
```

The expected magic value is:

```text
0x1626ba7e
```

Wrong magic values and contract reverts are clean invalid signatures.

RPC failures, ABI failures, and malformed return data are errors.

## ERC-6492 wrapper handling

ERC-6492 wrapped signatures are detected by exact 32-byte suffix:

```text
0x6492649264926492649264926492649264926492649264926492649264926492
```

The payload before the suffix must ABI-decode as:

```solidity
(address factory, bytes factoryData, bytes signature)
```

Suffix detection alone does not mean the wrapper is well formed.

`UnwrapERC6492` and `VerifyERC6492` still require the payload to ABI-decode successfully.

Malformed wrappers return errors.

## ERC-6492 verification errors

A clean `false` return from the configured deployed verifier is treated as an invalid ERC-6492 signature.

A deployed verifier call failure or revert is treated as an operational verifier error. This differs from direct EIP-1271 verification, where a contract revert is a clean invalid EIP-1271 result and may allow universal EOA fallback.

The package does not implement ERC-6492 prepare-call retry logic itself. When `WithERC6492Factory` is used, the wrapped signature is passed to the configured deployed verifier. Any deployment or prepare semantics depend on that verifier contract.

## Deployed verifier trust

ERC-6492 verification uses the deployed verifier address provided with `WithERC6492VerifierAddress`.

Callers are responsible for choosing a verifier contract appropriate for their network and trust model.

A malicious, incompatible, or incorrectly deployed ERC-6492 verifier can return incorrect results. Use a verifier whose source, deployment, and behavior you trust.

The library does not include a chain registry or manage verifier addresses.

## Deployless ERC-6492 verifier caution

Deployless ERC-6492 verification requires verifier bytecode. Before this package includes such bytecode, the project requires:

* pinned Solidity source,
* pinned compiler version,
* optimizer settings,
* documented bytecode origin,
* reproducible build instructions,
* documentation in `docs/verifier-bytecode.md`.

Until then, ERC-6492 verification without a configured deployed verifier returns `ErrDeploylessVerifierMissing`.

## Block state

Contract-based verification can depend on chain state.

EIP-1271 results can change when contract storage, ownership, modules, or signer configuration changes.

ERC-6492 results can depend on the configured verifier, factory calldata, account deployment state, and chain state.

Use `WithBlockNumber` if you need reproducible verification against a specific historical block.

## `From` address

`WithFrom` sets the `From` field on contract calls.

Use it only when required, because some contracts may depend on `msg.sender` during verification.

## RPC trust

Contract verification depends on the configured `ContractCaller` and `ContractCodeReader`.

A malicious, faulty, stale, or misconfigured RPC endpoint can affect results.

Use trusted infrastructure for security-sensitive verification.
