---
id: signature-replay
title: Signature Replay and Malleability
lens: signature-replay
impact: HIGH
tags: [swc-117, swc-121, signature, replay, eip712, fund-loss]
aliases: [replay, replay-attack]
triggers: ["ecrecover", "ECDSA.recover", "hashTypedData", "permit", "nonce", "DOMAIN_SEPARATOR", "block.chainid", "_hashTypedDataV4", "signature", "v, r, s"]
---

# Signature Replay and Malleability

A contract accepts a signed message to authorize an action but does not bind the
signature to a single use and a single chain, so the same signature is replayed: a second
time to repeat the action, on a forked or sibling chain with no chainid, or across
contracts with no domain separator. Recovering the signer with raw `ecrecover` without
checking it is nonzero accepts a zero-address signer, and unchecked `s` allows a malleable
second signature for the same message. Consume a per-signer nonce, bind the chainid and a
domain separator with EIP-712, and reject a zero signer.

## Vulnerable
```solidity
function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 h = keccak256(abi.encodePacked(to, amount));   // no nonce, no chainid, no domain
    address signer = ecrecover(h, v, r, s);                 // zero-address signer not rejected
    require(signer == admin);
    _transfer(to, amount);                                  // the same signature claims forever
}
```

## Secure
```solidity
function claim(address to, uint256 amount, bytes calldata sig) external {
    bytes32 h = _hashTypedDataV4(keccak256(abi.encode(CLAIM_TYPEHASH, to, amount, nonces[to]++)));
    require(ECDSA.recover(h, sig) == admin, "bad sig");     // EIP-712 domain + chainid, nonce consumed
    _transfer(to, amount);
}
```
