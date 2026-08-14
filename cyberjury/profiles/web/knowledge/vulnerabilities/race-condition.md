---
id: race-condition
title: Race Condition / TOCTOU
impact: HIGH
tags: [cwe-362, cwe-367, owasp-a04]
selection_hints: ["select_for_update", "transaction.atomic", "get_or_create", "compare_exchange", "compareAndSet", "compare-and-swap", "double spend", "double redemption", "FOR UPDATE"]
---

# Race Condition / TOCTOU

A check and the action it guards run on shared state without a lock or atomic update. Two
concurrent requests can both pass the check, enabling a double spend, duplicate redemption, or
limit bypass. The attacker must be able to overlap operations against the same state. Report the
check or dependent write where the non-atomic sequence is visible. Use a row lock, an atomic
conditional update, or a database invariant that makes only one operation succeed.

## Python

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

A check and the write it guards performed atomically is not a race, whatever the mechanism: the
row locked inside one transaction, a single conditional update that both tests and writes such as
a compare and set, a conditional `UPDATE ... WHERE`, or an atomic increment, or a unique constraint
or other database invariant that rejects the second writer. A framework expression evaluated in
the database is safe when its predicate or invariant also prevents the invalid second operation.
Report only when the check and its dependent write are separate, non-atomic steps on shared state.
