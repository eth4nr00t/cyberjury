---
id: reentrancy
title: Reentrancy
impact: CRITICAL
tags: [swc-107, reentrancy, fund-loss]
selection_hints: [".call{value", ".call(", "send(", "external call", "balances[", "withdraw", "nonReentrant", "safeTransfer", "onERC721Received", "tokensToSend", "tokensReceived", "ERC777", "before state", "read-only reentrancy", "get_virtual_price", "getReserves", "getRate", "sharePrice", "view returns"]
aliases: [read-only-reentrancy]
---

# Reentrancy

An external call before state is finalized lets the callee reenter against stale state. The
classic form repeats a withdrawal. Cross function reentrancy reaches a sibling entrypoint that
shares state. Read only reentrancy exposes a stale price, reserve, or share view while another
protocol acts on it. Token transfers are interactions too because ERC-777 and other tokens can
invoke hooks. Unless readable code fixes the token to a callback free implementation, inspect
every callback route and every shared invariant. Finalize state before interaction or guard all
entrypoints that can observe or mutate it. A guard cannot make an inconsistent view safe.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 balance = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: balance}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}

contract SecureBank {
    mapping(address => uint256) public balances;
    bool private entered;

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: balance}("");
        require(ok);
    }
}
```

## Not a Finding

An interaction is safe when all state shared by reachable callbacks is finalized first, or one
guard covers every relevant entrypoint. A token is callback free only when its implementation or
enforced allowlist is readable. A callback view is safe only when it reflects the transition and
no consumer can act on stale intermediate state.
