---
id: business-logic
title: Business Logic Flaw
impact: HIGH
tags: [cwe-840, cwe-841, owasp-a04]
selection_hints: ["request.json[\"price\"", "request.json[\"amount\"", "request.json.get(\"price\"", "request.json.get(\"amount\"", "req.body.price", "req.body.amount", "req.body.discount", "req.body.status"]
---

# Business Logic Flaw

A stateful workflow is vulnerable when an attacker can supply an authoritative value or reach a
transition without satisfying its prerequisites. Examples include charging a client supplied
price, accepting an unbounded quantity, redeeming the same entitlement twice, or approving an
object from the wrong state. The dangerous operation is the charge, credit, reservation,
entitlement grant, or state change that commits the invalid result. An attacker can obtain goods,
money, scarce capacity, or privileges outside the intended rules.

Report the line that commits the invalid operation. Show the attacker controlled value or
reachable state, the missing invariant, and a request sequence that produces the unauthorized
result. Recompute authoritative values from trusted records, bound client supplied quantities,
and enforce valid transitions atomically before committing the operation.

## Python

Vulnerable:

```python
def charge_order(payload, catalog, order):
    total = payload["price"] * payload["quantity"]
    order.charge(total)
```

Secure:

```python
def charge_order(payload, catalog, order):
    price = catalog[payload["product_id"]]
    quantity = int(payload["quantity"])
    if quantity < 1 or quantity > 10:
        raise ValueError("invalid quantity")
    order.charge(price * quantity)
```

## Not a Finding

A request field that is only a display hint, estimate, or lookup key is safe when the committed
value is recomputed from trusted state. A transition is safe when the reachable code checks its
prerequisites and updates the state atomically. Missing client side validation alone is not a
finding when the server enforces the same invariant before the dangerous operation.
