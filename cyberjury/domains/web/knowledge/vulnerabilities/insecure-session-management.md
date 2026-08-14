---
id: insecure-session-management
title: Insecure Session Management
impact: MEDIUM
tags: [cwe-384, cwe-613, cwe-614, owasp-a07]
selection_hints: ["set_cookie", "httponly", "secure=False", "SESSION_COOKIE_SECURE", "samesite", "SameSite=None", "session_id", "rotate_session", "regenerate_session", "remember_token"]
---

# Insecure Session Management

Session management is vulnerable when an attacker can choose or recover a session identifier and
the application continues to accept it as a victim's authenticated session. Exploitable cases
include preserving an attacker known id across login, sending the credential over cleartext, or
accepting it indefinitely after logout or expiry. Report the login, cookie creation, or session
validation line that preserves the usable identifier. Show how the attacker obtains it and which
authenticated action it unlocks.

Regenerate the identifier after authentication, transmit it only over HTTPS, keep it unavailable
to client script when script access is unnecessary, apply an effective SameSite policy, and
enforce idle and absolute expiry. A missing flag is reportable only when the deployment and an
attacker path make session theft or fixation concrete.

## Python

Vulnerable:

```python
def login(response, attacker_known_session_id):
    response.set_cookie("sid", attacker_known_session_id)
```

Secure:

```python
import secrets


def login(response, sessions, old_session_id, authenticated_user):
    sessions.invalidate(old_session_id)
    new_session_id = secrets.token_urlsafe(32)
    sessions.create(
        new_session_id,
        authenticated_user,
        idle_seconds=1_800,
        absolute_seconds=28_800,
    )
    response.set_cookie(
        "sid",
        new_session_id,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return new_session_id
```

## Not a Finding

A session id regenerated at authentication and invalidated at logout and expiry is not fixed or
indefinite. A cookie without `Secure` in a local test configuration is not a production transport
finding. Missing `HttpOnly` alone does not create script execution, and missing `SameSite` alone
belongs to a concrete CSRF analysis. Do not report a cookie flag from source defaults when a
reachable deployment configuration visibly supplies the effective secure value.
