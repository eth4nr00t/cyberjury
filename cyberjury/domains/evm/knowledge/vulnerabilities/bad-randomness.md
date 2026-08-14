---
id: bad-randomness
title: Insecure Randomness
impact: HIGH
tags: [swc-120, randomness, fund-loss]
selection_hints: ["block.timestamp", "blockhash", "block.difficulty", "block.prevrandao", "block.number", "keccak256(abi.encodePacked(block", "random", "lottery", "vrf"]
aliases: [weak-randomness, predictable-random]
---

# Insecure Randomness

A valuable outcome derived from `block.timestamp`, `blockhash`, `block.number`, or
`block.prevrandao` is predictable to callers and influenceable by a proposer. This can rig a
lottery, mint order, or valuable trait. Use verifiable randomness, or a commit and reveal
protocol that fixes every commitment before its seed is known.

Timestamp dependence is reportable only when a proposer can profit by moving a valuable boundary
within the chain's tolerance. Ordinary deadlines and coarse vesting schedules are not randomness.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

interface Coordinator {
    function request() external returns (uint256 requestId);
}

contract VulnerableLottery {
    uint256 public winner;

    function draw(uint256 players) external {
        require(players > 0);
        winner = uint256(keccak256(abi.encode(block.timestamp, block.prevrandao))) % players;
    }
}

contract SecureLottery {
    Coordinator public immutable coordinator;
    uint256 public immutable playerCount;
    mapping(uint256 => bool) public pending;
    uint256 public winnerIndex;
    bool public requested;
    bool public drawn;

    constructor(Coordinator trustedCoordinator, uint256 players) {
        require(players > 0, "no players");
        coordinator = trustedCoordinator;
        playerCount = players;
    }

    function requestDraw() external returns (uint256 requestId) {
        require(!requested);
        requested = true;
        requestId = coordinator.request();
        pending[requestId] = true;
    }

    function fulfillDraw(uint256 requestId, uint256 randomValue) external {
        require(msg.sender == address(coordinator) && pending[requestId] && !drawn);
        pending[requestId] = false;
        drawn = true;
        winnerIndex = randomValue % playerCount;
    }
}
```

## Not a Finding

Block time is safe for a coarse delay when a proposer's practical influence cannot change a
valuable result. Random selection is safe when an authenticated coordinator binds unpredictable
output to a recorded request, or commitments are fixed before any party learns the combined seed.
