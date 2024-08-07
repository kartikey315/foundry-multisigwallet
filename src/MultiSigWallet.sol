// Inside each contract, library or interface, use the following order:
// Type declarations
// State variables
// Events
// Errors
// Modifiers
// Functions

// Layout of Functions:
// constructor
// receive function (if exists)
// fallback function (if exists)
// external
// public
// internal
// private
// internal & private view & pure functions
// external & public view & pure functions

// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

abstract contract ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(
        bytes32 hash,
        bytes memory signature
    ) public pure returns (address) {
        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
        } else if (signature.length == 64) {
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let vs := mload(add(signature, 0x40))
                r := mload(add(signature, 0x20))
                s := and(
                    vs,
                    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                )
                v := add(shr(255, vs), 27)
            }
        } else {
            revert("ECDSA: invalid signature length");
        }
        return recover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        require(
            uint256(s) <=
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "ECDSA: invalid signature 's' value"
        );
        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");
        return signer;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(
        bytes32 hash
    ) public pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, structHash)
            );
    }
}
contract MultiSigWallet is ECDSA, Initializable, UUPSUpgradeable, Ownable {
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;

    uint256 private s_minRequiredSignatures;
    address[] private s_signers;
    mapping(address => bool) private s_isSigner;
    mapping(bytes32 => bool) private hashUsed;

    event MultiSigWalletInitialzed(
        address[] signers,
        uint256 minRequiredSignatures
    );

    error MultiSigWallet_NoOwners();
    error MultiSigWallet_NotSigner();
    error MultiSigWallet_WrongSignature();
    error MultiSigWallet_HashUsed();

    modifier onlySigners() {
        if (s_isSigner[msg.sender] == false) {
            revert MultiSigWallet_NotSigner();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    function initialize(
        address[] memory initialOwners,
        uint256 minRequiredSignatures
    ) public initializer {
        _initialize(initialOwners, minRequiredSignatures);
    }

    function execute(
        address dest,
        bytes calldata functionData,
        bytes calldata signature,
        bytes32 unsignedHash
    ) external onlySigners {
        if (hashUsed[unsignedHash] == true) {
            revert MultiSigWallet_HashUsed();
        }
        if (checkSignature(signature, unsignedHash) == SIG_VALIDATION_FAILED) {
            revert MultiSigWallet_WrongSignature();
        }

        hashUsed[unsignedHash] = true;

        _call(dest, functionData);
    }

    function checkSignature(
        bytes calldata signature,
        bytes32 unsignedHash
    ) public view returns (uint256) {
        bytes32 hash = toEthSignedMessageHash(unsignedHash);
        bytes[] memory signatures = abi.decode(signature, (bytes[]));
        uint256 noOfSignatures;
        for (uint256 i = 0; i < signatures.length; i++) {
            address ownerAddress = recover(hash, signatures[i]);
            if (s_isSigner[ownerAddress]) {
                noOfSignatures++;
            }
        }

        if (noOfSignatures >= s_minRequiredSignatures) {
            return SIG_VALIDATION_SUCCESS;
        }
        return SIG_VALIDATION_FAILED;
    }

    function getMinimumRequiredSignatures() external view returns (uint256) {
        return s_minRequiredSignatures;
    }

    function getSigners() external view returns (address[] memory) {
        return s_signers;
    }

    function getTransactionHash(
        address dest,
        bytes calldata functionData
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(dest, functionData, block.timestamp));
    }

    function _initialize(
        address[] memory initialOwners,
        uint256 minRequiredSignatures
    ) internal {
        if (initialOwners.length == 0) {
            revert MultiSigWallet_NoOwners();
        }
        s_signers = initialOwners;
        for (uint256 i = 0; i < initialOwners.length; i++) {
            s_isSigner[initialOwners[i]] = true;
        }
        s_minRequiredSignatures = minRequiredSignatures;

        emit MultiSigWalletInitialzed(initialOwners, minRequiredSignatures);
    }

    function _call(address target, bytes calldata data) internal {
        (bool success, ) = target.call(data);
        if (!success) {
            revert("Execution Failed");
        }
    }

    function _authorizeUpgrade(address) internal view override {}

    receive() external payable {}
}
