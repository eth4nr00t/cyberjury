---
id: insecure-direct-object-reference
title: Insecure Direct Object Reference
impact: HIGH
tags: [cwe-639, owasp-a01, access-control]
selection_hints: ["objects.get(", "get_object_or_404", "findById", "findByPk", "findUnique", "/<id>", "/:id", "request.args.get(\"id\"", "request.args['id']", "req.params.id", "params[\"id\"", "pk=", "where id =", "where: { id", "owner_id", "tenant_id"]
---

# Insecure Direct Object Reference

## Security Condition

A record is fetched or mutated by an attacker supplied identifier without checking that the
authenticated caller may access it. Changing the identifier then exposes or modifies another user's,
tenant's, or service's data.

## Review Guidance

Report the lookup or mutation that first crosses the access boundary. Show the attacker controlled
identifier, the missing ownership or tenant scope, and the protected data or action reached. Scope
every object lookup to the verified caller or tenant.

## Examples

### Object Ownership Scope

Vulnerable:

```python
def get_account(account_model, account_id):
    return account_model.objects.get(id=account_id)
```

Secure:

```python
def get_account(get_object_or_404, account_model, account_id, verified_owner):
    return get_object_or_404(account_model, id=account_id, owner=verified_owner)
```

## Not a Finding

A lookup that reads as fetch by id may already be scoped to the caller when that scope is visible in
the reachable code. Ownership may come from an association rooted at the authenticated principal,
an explicit owner or tenant predicate, or a separate authorization decision before the lookup.
When a control you can read binds the requested object to the caller, the lookup is not an IDOR.
An object that the documented policy intentionally exposes to every caller also has no protected
access boundary.

Do not assume an invisible framework scope or middleware control. When the reviewed code does not
show the effective scope, preserve the candidate and identify the exact fact needed to resolve it,
such as the generated query or the policy applied on the reachable path. A bare fetch by id with no
readable scope and no separate authorization check crosses the access boundary.
