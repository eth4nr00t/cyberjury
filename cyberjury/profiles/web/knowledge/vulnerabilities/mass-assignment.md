---
id: mass-assignment
title: Mass Assignment
impact: HIGH
tags: [cwe-915, owasp-a04, owasp-a08]
selection_hints: ["(**request", "update(**", "setattr(", "Object.assign", "create(**", "request.get_json", "req.body", "update(req.body", "create(req.body", "Model(**", "model_validate", "parse_obj", "serializer.save"]
---

# Mass Assignment

## Security Condition

Binding an attacker controlled request map directly into a persistent model or update can expose
fields the public operation was never intended to accept. The issue is exploitable when a writable
field controls privilege, ownership, approval, balance, workflow state, or another protected
property.

## Review Guidance

Report the model creation or mutation that consumes the broad map. Identify the sensitive writable
field and the unauthorized outcome an attacker obtains. Bind only an explicit allowlist of public
fields.

## Examples

### Explicit Mutable Field Selection

Vulnerable:

```python
def create_user(user_model, request):
    return user_model(**request.get_json())
```

Secure:

```python
def create_user(user_model, request):
    body = request.get_json()
    return user_model(name=body["name"], email=body["email"])
```

## Not a Finding

Whole-object binding is safe when a schema rejects or strips every field outside a closed public
allowlist before persistence, and the code shown uses only that validated output. A model with no
sensitive writable fields is not exploitable merely because it accepts a map. Type checking or
sanitizing values does not prevent assignment to a field that the caller must not control.
