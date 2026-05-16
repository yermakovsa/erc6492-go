// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Tiny EIP-1271 fixture wallet. Not for production use.
contract ExampleEIP1271Wallet {
    bytes4 public constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    bytes4 public constant INVALID_SIGNATURE_VALUE = 0xffffffff;

    /// @dev secp256k1n / 2, used to reject malleable signatures.
    uint256 public constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable owner;

    error ZeroOwner();

    constructor(address owner_) {
        if (owner_ == address(0)) {
            revert ZeroOwner();
        }

        owner = owner_;
    }

    /// @notice Validates a 65-byte r || s || v signature against the exact input hash.
    /// @dev No prefixing, typed-data hashing, or v = 0/1 normalization.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 65) {
            return INVALID_SIGNATURE_VALUE;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        if (uint256(s) > SECP256K1_HALF_ORDER) {
            return INVALID_SIGNATURE_VALUE;
        }

        if (v != 27 && v != 28) {
            return INVALID_SIGNATURE_VALUE;
        }

        address recovered = ecrecover(hash, v, r, s);

        if (recovered == owner) {
            return EIP1271_MAGIC_VALUE;
        }

        return INVALID_SIGNATURE_VALUE;
    }
}