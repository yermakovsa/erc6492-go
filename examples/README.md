# Examples

Small examples for using `erc6492-go`.

The examples verify caller-supplied final hashes. They do not build messages, hash typed data, send transactions, or deploy contracts.

## Available examples

- [`eoa`](./eoa) verifies a known EOA signature locally.
- [`eip1271`](./eip1271) verifies a known EIP-1271 signature against a fixture contract on Sepolia.