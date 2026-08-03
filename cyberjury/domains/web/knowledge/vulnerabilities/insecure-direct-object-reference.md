---
id: insecure-direct-object-reference
title: Insecure Direct Object Reference
lens: authorization
impact: HIGH
tags: [cwe-639, owasp-a01, access-control]
triggers: ["objects.get(", "findById", "get_object_or_404", "/<id>", "/:id", "request.args", "params[", "pk=", "where id ="]
---

# Insecure Direct Object Reference

A record is fetched or mutated by a user-supplied id without checking the caller owns or may access it, so an authenticated user reaches another user's, tenant's, or service's data by changing the id. Scope every object lookup to the caller's identity or tenant.

## Python, Django
Vulnerable:
```python
account = Account.objects.get(id=request.GET["account_id"])
```
Secure:
```python
account = get_object_or_404(Account, id=request.GET["account_id"], owner=request.user)
```

## Node.js, Express
Vulnerable: `const doc = await Document.findById(req.params.id)`
Secure: `const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id })`

## Judge the Effective Scope, but Only on a Scope You Can Read

A lookup that reads as fetch-by-id may already be scoped to the caller when the scope is visible in the code you read. Ownership often comes from the object the query is built on, not a literal `where owner = ?`: an association chain scopes to the caller such as Rails `current_user.posts.find(id)` or Laravel `$user->posts()->find($id)`, and an explicit filter scopes it such as Django `request.user.accounts.get(pk=id)`. When a scope you can read binds the query to the caller on the reachable path, the fetch-by-id is not an IDOR.

Do not clear a fetch-by-id on a scope you cannot read. An implicit framework auto-scope is an assumed off-file control, not a fact you read: an ORM that folds a struct's set fields into the WHERE such as xorm autocondition, a default manager or default scope, a tenant middleware. When a bare fetch-by-id would cross tenants and the only thing that might save it is such an implicit auto-scope, mark the finding blocked with the exact fact to verify, the generated query or a runnable request, never refuted. Recall comes first, an assumed implicit scope does not clear a finding, a bare fetch-by-id with no readable scoping and no separate authorization check is the real defect.
