---
id: missing-authorization
title: Missing Authorization
lens: authorization
impact: HIGH
tags: [cwe-862, owasp-a01, access-control]
triggers: ["@app.route", "@router", "@login_required", "requires_", "permission", "is_admin", "role", "def delete", "def admin"]
---

# Missing Authorization

A privileged or state-changing endpoint performs its action without verifying the caller is allowed to, or derives the role/permission from a client-controlled value. Enforce authorization server-side, per request, from a trusted store. A route that mutates or exposes privileged data must check the caller's rights the same way its peers do. Authorization answers whether this caller may perform the action or reach the resource. Compare improper-authentication, which answers who the caller is, so route client-controlled role or permission here.

## Python
Vulnerable:
```python
@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):  # no authorization check
    User.objects.get(id=uid).delete()


is_admin = request.json["is_admin"]  # privilege from the client
```
Secure:
```python
@app.route("/admin/users/<uid>", methods=["DELETE"])
@requires_admin
def delete_user(uid):
    User.objects.get(id=uid).delete()
```
