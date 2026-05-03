# ERC-6492 verifier bytecode

Deployless ERC-6492 verification is not implemented.

This package currently supports ERC-6492 verification only through a deployed verifier contract configured with `WithERC6492VerifierAddress`.

## Current status

No deployless verifier bytecode is currently embedded in this repository.

If ERC-6492 verification is attempted without a configured deployed verifier address, the package returns `ErrDeploylessVerifierMissing` instead of attempting deployless verification.

## Why this is guarded

Deployless verification requires embedding, constructing, or otherwise supplying verifier bytecode. That bytecode becomes part of the library's security boundary.

Including unknown, unpinned, or unreproducible bytecode would make the implementation difficult to audit.

Reference implementations such as AmbireTech `signature-validator` and viem include deployless verifier bytecode, but this project does not copy bytecode without reproducible provenance.

## Requirements before deployless support

Before adding deployless verifier bytecode, document:

* pinned Solidity source,
* source license,
* exact compiler version and build, for example `solc 0.8.x+commit...`,
* optimizer enabled/disabled status,
* optimizer run count if enabled,
* dependency versions if the build uses external libraries,
* bytecode origin,
* reproducible build instructions,
* final bytecode,
* bytecode hash,
* ABI compatibility notes for deployed and deployless verifier paths,
* verification notes.

## Review checklist

Before deployless support is enabled:

* bytecode can be reproduced from documented source and compiler settings,
* reproduced bytecode hash matches the committed bytecode,
* ABI matches the Go encoder/decoder expectations,
* behavior is compared against ERC-6492 reference behavior,
* tests cover valid, invalid, malformed, and revert cases,
* README and security notes are updated.

## Rule

Do not invent verifier bytecode.

Do not paste unverified verifier bytecode.

Do not add deployless verification without reproducible provenance.
