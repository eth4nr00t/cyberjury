---
id: improper-authentication
title: Improper Authentication
impact: HIGH
tags: [cwe-287, cwe-306, owasp-a07]
selection_hints: ["authenticate(", "login_user", "verify_password", "password ==", "== token", "Authorization", "is_authenticated", "current_user", "bypass", "if not user", "anonymous"]
---

# Improper Authentication

## Security Condition

Authentication is vulnerable when a protected operation accepts no credential, trusts a
client-asserted identity, or contains a bypass that lets an attacker become an authenticated
principal. The dangerous operation is the session creation or protected action reached under the
forged identity.

## Review Guidance

Report that operation or its authentication gate, and show the attacker controlled assertion or
credential plus the path that bypasses verification against a trusted store. Authentication
establishes who the caller is. Missing authorization is the separate case where a verified caller is
not allowed to perform the action.

## Examples

### Server Verified Identity

Vulnerable:

```python
def account_dashboard(request, render_account):
    username = request.headers["X-User"]
    return render_account(username)
```

Secure:

```python
def account_dashboard(request, sessions, render_account):
    user = sessions.authenticate(request.cookies.get("sid"))
    if user is None:
        raise PermissionError("authentication required")
    return render_account(user.name)
```

## Not a Finding

A public endpoint does not require authentication. A protected operation is safe when the
reachable path verifies a credential against trusted server state before establishing the
principal. A caller supplied user id is safe only as a lookup key when the verified credential is
still bound to the resulting identity. A plain secret comparison is not by itself a reportable
authentication bypass without a practical way to forge, recover, or skip the credential.
