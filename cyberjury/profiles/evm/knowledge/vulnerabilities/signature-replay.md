---
id: signature-replay
title: Signature Replay and Malleability
impact: HIGH
tags: [swc-117, swc-121, signature, replay, eip712, fund-loss]
selection_hints: ["ecrecover", "ECDSA.recover", "hashTypedData", "_hashTypedDataV4", "toEthSignedMessageHash", "permit", "nonce", "DOMAIN_SEPARATOR", "block.chainid", "chainId", "EIP712", "signature", "v, r, s"]
aliases: [replay, replay-attack]
---

# Signature Replay and Malleability

A signed action is replayable when its digest does not bind a single use, chain, contract, action,
and arguments. A time limited authorization must also bind and enforce its expiry. Raw `ecrecover`
needs a nonzero signer, valid `v`, and low `s` to reject malleable signatures. Consume a signer
nonce atomically and use an EIP-712 domain separator.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableClaim {
    address public immutable admin;
    mapping(address => uint256) public credits;

    constructor(address trustedAdmin) {
        admin = trustedAdmin;
    }

    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        require(ecrecover(digest, v, r, s) == admin);
        credits[to] += amount;
    }
}

contract SecureClaim {
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("Claim(address to,uint256 amount,uint256 nonce,uint256 deadline)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable admin;
    uint256 public nonce;
    mapping(address => uint256) public credits;

    constructor(address trustedAdmin) {
        require(trustedAdmin != address(0));
        admin = trustedAdmin;
    }

    function claim(address to, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        require(v == 27 || v == 28);
        require(uint256(s) <= HALF_ORDER);
        bytes32 data = keccak256(abi.encode(CLAIM_TYPEHASH, to, amount, nonce, deadline));
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, block.chainid, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, data));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == admin, "bad signature");
        nonce += 1;
        credits[to] += amount;
    }
}
```

## Not a Finding

A signed action is safe when its digest binds the contract, chain, action, arguments, and nonce,
and success consumes the nonce. Bind expiry when the authorization is time limited. A vetted ECDSA
helper closes malleability. Reusing a signature for an idempotent read with no authorization or
value effect is not reportable.
