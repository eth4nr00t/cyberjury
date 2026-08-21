---
id: race-condition
title: Race Condition / TOCTOU
impact: HIGH
tags: [cwe-362, cwe-367, owasp-a04]
selection_hints: ["select_for_update", "transaction.atomic", "get_or_create", "compare_exchange", "compareAndSet", "compare-and-swap", "double spend", "double redemption", "FOR UPDATE"]
---

# Race Condition / TOCTOU

## Security Condition

A check and the action it guards run on shared state without a lock or atomic update. Two concurrent
requests can both pass the check, enabling a double spend, duplicate redemption, or limit bypass.
The attacker must be able to overlap operations against the same state.

## Review Guidance

Report the check or dependent write where the non-atomic sequence is visible. Use a row lock, an
atomic conditional update, or a database invariant that makes only one operation succeed.

## Examples

### Atomic Conditional State Update

Vulnerable:

```python
def debit(connection, account_id: int, amount: int) -> bool:
    if amount <= 0:
        return False
    row = connection.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if row is None or row[0] < amount:
        return False
    connection.execute("UPDATE accounts SET balance = ? WHERE id = ?", (row[0] - amount, account_id))
    connection.commit()
    return True
```

Secure:

```python
def debit(connection, account_id: int, amount: int) -> bool:
    if amount <= 0:
        return False
    result = connection.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
        (amount, account_id, amount),
    )
    connection.commit()
    return result.rowcount == 1
```

## Not a Finding

A check and the write it guards performed atomically is not a race. A row lock held across one
transaction serializes the operation. A conditional update can test and write in one step, such as
a compare and set or a conditional `UPDATE ... WHERE`. An atomic increment is safe when no separate
check controls it. A unique constraint or another database invariant can reject the second writer.
A framework expression evaluated in the database is safe when its predicate or invariant also
prevents the invalid second operation.
Report only when the check and its dependent write are separate, non-atomic steps on shared state.
