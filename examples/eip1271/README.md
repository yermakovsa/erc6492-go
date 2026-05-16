# EIP-1271 example

This example verifies a known EIP-1271 signature against a small fixture contract deployed on Sepolia.

It uses a final `bytes32` hash directly. It does not hash messages, build typed data, send transactions, or deploy anything.

## Fixture

- Chain: Sepolia
- Contract: `0x01719b210cca35ee34f46007daed7fb359086f91`
- Verified source: https://sepolia.etherscan.io/address/0x01719b210cca35ee34f46007daed7fb359086f91#code
- Owner: `0x3c002f761491bea2b25A8321490f9ca7A87B4DCf`
- Hash: `0x3dec0f6a98cd6082f478ae1d655bf12eb7c2c52be60e011c91a5ae1f62670b5c`
- Expected result: `0x1626ba7e`

`ExampleEIP1271Wallet.sol` is included here only so the fixture contract is easy to inspect.

The tested Solidity fixture repo is:

https://github.com/yermakovsa/example-eip1271-wallet

## Run

From the repository root:

```bash
RPC_URL="<your Sepolia RPC URL>" go run ./examples/eip1271
````

Expected output:

```text
valid: true
method: eip1271
```