---
id: replay-attack
title: Replay Attack
impact: HIGH
tags: [cwe-294, owasp-a04]
selection_hints: ["verify_sig(", "verify_signature(", "consume_nonce(", "within_window(", "Idempotency-Key", "X-Signature", "X-Hub-Signature", "X-Webhook-Timestamp", "replay cache", "replay attack"]
---

# Replay Attack

A signed or privileged request such as a payment, webhook, or login assertion is accepted again
because its freshness or unique identifier is not checked. An attacker who can capture or obtain
one valid request replays it to repeat the privileged effect. Bind the signature to the complete
sensitive request and enforce a short timestamp window plus a unique nonce, event identifier, or
idempotency key that is consumed atomically. Report the verification or dispatch location where a
valid duplicate can reach the sensitive operation.

## Python

Vulnerable:

```python
def handle_payment(body: dict, signature: str, verifier, payments) -> None:
    if verifier(body, signature):
        payments.create(body)
```

Secure:

```python
def handle_payment(body: dict, signature: str, verifier, nonce_store, payments) -> None:
    if not verifier(body, signature):
        raise PermissionError("invalid signature")
    if not nonce_store.consume_once(body["nonce"], body["timestamp"]):
        raise ValueError("expired or reused request")
    payments.create(body)
```

## Not a Finding

A signed request is safe when the receiver or a trusted upstream verifier enforces freshness and
atomically consumes a unique request identifier before the side effect. A transactionally enforced
idempotency key that returns the original result without repeating the effect is also safe. A
timestamp check alone still permits replay within its window. Do not report a duplicate delivery
when the operation is inherently idempotent and no repeated security impact is possible.
