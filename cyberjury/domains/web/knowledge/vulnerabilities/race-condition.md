---
id: race-condition
title: Race Condition / TOCTOU
lens: race-condition
impact: HIGH
tags: [cwe-362, cwe-367, owasp-a04]
triggers: ["if balance", "balance -=", "select_for_update", "get(...).save", "check", "transaction", "lock", "atomic"]
---

# Race Condition / TOCTOU

A check and the action it guards run on shared state without a lock or atomic update, so two concurrent requests both pass the check, enabling double-spend, double-redeem, or a limit bypass. Use a row lock, an atomic conditional update, or a transaction.

## Python, Django
Vulnerable:
```python
acct = Account.objects.get(pk=pk)
if acct.balance >= amount:  # concurrent requests both pass this check
    acct.balance -= amount
    acct.save()
```
Secure:
```python
with transaction.atomic():
    acct = Account.objects.select_for_update().get(pk=pk)
    if acct.balance >= amount:
        acct.balance -= amount
        acct.save()
```

## Not a Finding

A check and the write it guards performed atomically is not a race, whatever the mechanism: the
row locked inside one transaction, a single conditional update that both tests and writes such as
a compare-and-set, a conditional `UPDATE ... WHERE`, or an atomic increment, or a unique constraint
or other database invariant that rejects the second writer. The Django form above,
`transaction.atomic()` with `select_for_update()` or an `F()` update, is one example. Report only
when the check and its dependent write are separate, non-atomic steps on shared state.
