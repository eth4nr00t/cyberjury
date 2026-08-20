---
id: unchecked-low-level-call
title: Unchecked Low-Level Call
impact: HIGH
tags: [swc-104, low-level-call, return-value, fund-loss]
selection_hints: [".call(", ".call{value", ".delegatecall(", ".send(", "bool success", "bool ok", "(bool", "success,", "returndata", "returndatacopy", "abi.decode(returndata", "excessivelySafeCall"]
aliases: [unchecked-call, unchecked-return]
---

# Unchecked Low-Level Call

Low level calls separate EVM execution status from returned application data. A caller must check
the status, interpret any required return value, and bound attacker controlled return data before
copying it. These controls address distinct failure modes.

## Ignored Call Status

Low level primitives such as `.call`, `.delegatecall`, and `.send` report EVM failure as a boolean.
Recording completion after an ignored failure can erase a debt even though no value moved.

```solidity
pragma solidity ^0.8.20;

contract VulnerablePayout {
    mapping(address => uint256) public owed;

    function fund(address recipient) external payable {
        owed[recipient] += msg.value;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).call{value: amount}("");
    }
}

contract SecurePayout {
    mapping(address => uint256) public owed;

    function fund(address recipient) external payable {
        owed[recipient] += msg.value;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

## Optional Token Return Values

A raw token call may succeed at the EVM level and still return an encoded `false`. Some deployed
tokens return no value on success. Accept empty return data only under the intended optional return
contract, reject explicit `false`, and ensure the target contains code.

```solidity
pragma solidity ^0.8.20;

contract VulnerableTokenCall {
    function transfer(address token, address recipient, uint256 amount) external {
        (bool ok,) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", recipient, amount)
        );
        require(ok, "call failed");
    }
}

contract SecureTokenCall {
    function transfer(address token, address recipient, uint256 amount) external {
        require(token.code.length > 0, "not a token");
        (bool ok, bytes memory result) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", recipient, amount)
        );
        require(ok, "call failed");
        require(result.length == 0 || abi.decode(result, (bool)), "token returned false");
    }
}
```

## Unbounded Return Data

Assigning arbitrary return data to `bytes` copies it into memory. A malicious target can return or
revert with enough data to exhaust the caller's remaining gas. Copy only a fixed maximum when the
complete payload is not required.

```solidity
pragma solidity ^0.8.20;

contract VulnerableReturnCopy {
    function invoke(address target, bytes calldata input) external returns (bytes memory output) {
        (bool ok, bytes memory data) = target.call(input);
        require(ok, "call failed");
        return data;
    }
}

contract SecureReturnCopy {
    uint256 private constant MAX_COPY = 256;

    function invoke(address target, bytes calldata input)
        external
        returns (bytes memory output)
    {
        require(target.code.length > 0, "not code");
        bytes memory payload = input;
        output = new bytes(MAX_COPY);
        bool ok;
        assembly {
            ok := call(gas(), target, 0, add(payload, 32), mload(payload), add(output, 32), MAX_COPY)
            let size := returndatasize()
            if lt(size, MAX_COPY) { mstore(output, size) }
        }
        require(ok, "call failed");
    }
}
```

## Not a Finding

Ignoring failure is safe for a best effort notification only when no value, authority, or
completion record depends on success. A token wrapper is controlling evidence when its readable
implementation enforces the intended optional return convention and checks the target. Return data
is safe when a trusted target bounds it or the caller caps the bytes copied before allocation or
decoding.
