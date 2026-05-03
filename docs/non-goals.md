# Non-goals

This document describes the current scope of `erc6492-go`.

The project is under active development, and the API may change before the first tagged release.

The current implementation does not include:

* SIWE message construction,
* EIP-191 prefixing,
* EIP-712 typed-data hashing,
* raw message hashing,
* transaction sending,
* wallet deployment transactions,
* bundler integration,
* paymaster logic,
* account-abstraction framework support,
* ERC-4337 UserOperation helpers,
* ERC-8010,
* EIP-7702 authorization-list support,
* chain registry,
* internal RPC client management,
* caching or indexing,
* deployless ERC-6492 verification without documented bytecode provenance,
* trading, MEV, exchange, or order-building features.

## Core boundary

The library verifies whether an Ethereum address signed an already-computed `common.Hash`.

Anything before that hash exists is outside the package scope.

## No message construction

The package does not transform user-facing messages into hashes.

Callers must perform any required message formatting, domain separation, prefixing, or typed-data hashing outside this library.

## No transaction or deployment side effects

The package does not send transactions, deploy wallets, sponsor gas, use bundlers, or manage paymasters.

ERC-6492 factory, deployment, or prepare semantics, if any, are handled inside the configured verifier contract during `eth_call`.

## No unverified deployless verifier bytecode

The package does not embed or use deployless ERC-6492 verifier bytecode.

Deployless verification requires documented, reproducible verifier bytecode provenance before it can be implemented.

## No registry

The package does not maintain chain-specific verifier addresses or network metadata.

Callers must provide verifier addresses explicitly when using the deployed ERC-6492 verifier path.

## No caching or indexing

The package does not cache contract code, verification results, factory data, wallet deployments, or RPC responses.

Callers that need caching should implement it outside the library.
