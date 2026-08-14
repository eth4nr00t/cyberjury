---
id: missing-authorization
title: Missing Authorization
impact: HIGH
tags: [cwe-862, owasp-a01, access-control]
selection_hints: ["@permission_required", "has_permission(", "has_perm(", "authorize(", "is_admin", "admin_only", "requireRole(", "hasRole(", "AccessDenied", "PermissionDenied"]
---

# Missing Authorization

A privileged or state changing endpoint performs its action without verifying that the authenticated
caller may perform it, or it derives a role or permission from client controlled input. An attacker
can invoke the operation directly and read privileged data, modify protected state, or perform an
administrative action. Enforce authorization on every request from trusted server state.

Report the route or service call that reaches the privileged operation without the required
decision. Authorization answers whether this caller may perform the action. Improper authentication
answers who the caller is, so a client controlled role or permission belongs here.

## Python

Vulnerable:

```python
def delete_user(request_body: dict, users: dict) -> None:
    if request_body.get("is_admin"):
        del users[request_body["user_id"]]
```

Secure:

```python
def delete_user(actor, user_id: str, users: dict) -> None:
    if "admin" not in actor.roles:
        raise PermissionError("admin role required")
    del users[user_id]
```

The secure example assumes `actor` comes from the authenticated server session, not from the
request body.

## Not a Finding

Authentication alone is not authorization. The flow is safe when a route, middleware, service,
or data access layer checks the authenticated caller's required role, permission, tenant, or
resource relationship before the operation. A public operation is also safe when the intended
policy explicitly permits every caller. Do not report an absent check at the route when a
controlling authorization decision is visible in a called layer.
