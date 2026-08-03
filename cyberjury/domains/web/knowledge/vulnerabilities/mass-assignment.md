---
id: mass-assignment
title: Mass Assignment
lens: mass-assignment
impact: HIGH
tags: [cwe-915, owasp-a04, owasp-a08]
triggers: ["(**request", "update(**", "setattr(", "Object.assign", "create(**", "request.get_json", ".save()"]
---

# Mass Assignment

Binding a whole request body into a model or update lets a client set internal fields it was never offered such as is_admin, balance, or role. Bind only an explicit allowlist of fields.

## Python
Vulnerable:
```python
user = User(**request.get_json())
```
Secure:
```python
body = request.get_json()
user = User(name=body["name"], email=body["email"])
```
