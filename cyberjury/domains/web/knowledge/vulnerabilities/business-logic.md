---
id: business-logic
title: Business Logic Flaw
lens: business-logic
impact: HIGH
tags: [cwe-840, cwe-841, owasp-a04]
triggers: ["price", "amount", "quantity", "balance", "status", "approve", "discount", "total =", "request.json[\"price\"", "if status =="]
---

# Business Logic Flaw

A stateful workflow trusts client-supplied values or does not enforce its own rules: a client-set price/amount/quantity, a state-machine step reached without its prerequisites, an approval or limit bypassed. Validate amounts and state transitions server-side from trusted data, and enforce the workflow's invariants.

## Python
Vulnerable:
```python
total = request.json["price"] * request.json["qty"]  # client sets the price
order.charge(total)
```
Secure:
```python
price = Product.objects.get(id=pid).price  # price from the server
total = price * validate_qty(request.json["qty"])
```
