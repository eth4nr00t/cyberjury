---
id: bad-randomness
title: Insecure Randomness
lens: bad-randomness
impact: HIGH
tags: [swc-120, randomness, fund-loss]
aliases: [weak-randomness, predictable-random]
triggers: ["block.timestamp", "blockhash", "block.difficulty", "block.prevrandao", "block.number", "keccak256(abi.encodePacked(block", "random", "% "]
---

# Insecure Randomness

Deriving an outcome that controls value, a lottery winner, an NFT trait, a mint order, or
a selection, from on-chain data such as `block.timestamp`, `blockhash`, `block.number`, or
`block.prevrandao` is predictable. A caller computes the same value in the same block, and
a validator can influence or withhold it, so the result is gamed and the payout is stolen.
Use a verifiable randomness source such as a VRF, or a commit-reveal scheme where the seed
is fixed before it can be known.

The timestamp-dependence variant is the same root cause applied to time, not selection: a
proposer can nudge `block.timestamp` by a few seconds, so logic that gates an auction close,
a vesting unlock, a deadline, or a reward rate on an exact `block.timestamp` comparison is
manipulable at the margin. Use a tolerance band, a block-number gate, or an oracle time
rather than trusting `block.timestamp` to the second.

## Vulnerable
```solidity
function drawWinner(address[] calldata players) external {
    uint256 i = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % players.length;
    _payout(players[i]);   // any player predicts i in the same block
}
```

## Secure
```solidity
function drawWinner(uint256 requestId) external {
    uint256 random = vrf.randomness(requestId);   // unpredictable until the VRF fulfills
    uint256 i = random % playerCount;
    _payout(players[i]);
}
```
