---
id: business-logic
title: Business Logic Flaw
impact: HIGH
tags: [cwe-840, cwe-841, owasp-a04]
selection_hints: ["request.json[\"price\"", "request.json[\"amount\"", "request.json.get(\"price\"", "request.json.get(\"amount\"", "req.body.price", "req.body.amount", "req.body.discount", "req.body.status"]
---

# Business Logic Flaw

## Security Condition

A stateful workflow is vulnerable when an attacker can supply an authoritative value, exceed a
business bound, reuse a one time entitlement, or reach a transition without satisfying its
prerequisites. The dangerous operation is the charge, credit, reservation, grant, or state change
that commits the invalid result.

## Review Guidance

Report that operation with the attacker controlled value or reachable state, the missing invariant,
and the request sequence that produces the unauthorized result.

## Examples

### Authoritative Values

Vulnerable:

```python
def charge_order(payload, order):
    order.charge(payload["price"])
```

Secure:

```python
def charge_order(payload, catalog, order):
    price = catalog[payload["product_id"]]
    order.charge(price)
```

### Bounded Inputs

Vulnerable:

```python
def reserve_items(payload, inventory):
    inventory.reserve(payload["sku"], int(payload["quantity"]))
```

Secure:

```python
def reserve_items(payload, inventory):
    quantity = int(payload["quantity"])
    if quantity < 1 or quantity > 10:
        raise ValueError("invalid quantity")
    inventory.reserve(payload["sku"], quantity)
```

### One Time Entitlements

Vulnerable:

```python
def redeem(code, entitlements, account):
    value = entitlements.get(code)
    account.credit(value)
```

Secure:

```python
def redeem(code, entitlements, account):
    value = entitlements.consume_once(code)
    account.credit(value)
```

The consume operation must reject a used entitlement atomically before the credit is committed.

### State Transitions

Vulnerable:

```python
def update_order(order, payload):
    order.status = payload["status"]
    order.save()
```

Secure:

```python
def approve_order(orders, order_id):
    changed = orders.transition(order_id, expected="pending", target="approved")
    if not changed:
        raise ValueError("order is not pending")
```

## Not a Finding

A request field that is only a display hint, estimate, or lookup key is safe when the committed
value is recomputed from trusted state. A bounded input is safe when the server enforces the real
business limit before reserving or charging. A one time entitlement is safe when consumption and
the dependent effect cannot both succeed twice. A transition is safe when reachable code checks
its prerequisites and updates state atomically. Missing client side validation alone is not a
finding when the server enforces the same invariant before the dangerous operation.
