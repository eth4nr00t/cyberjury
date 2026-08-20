---
id: insecure-session-management
title: Insecure Session Management
impact: MEDIUM
tags: [cwe-384, cwe-613, cwe-614, owasp-a07]
selection_hints: ["set_cookie", "httponly", "secure=False", "SESSION_COOKIE_SECURE", "samesite", "SameSite=None", "session_id", "rotate_session", "regenerate_session", "remember_token"]
---

# Insecure Session Management

Session management is vulnerable when an attacker can choose or recover a session identifier and
the application continues to accept it as a victim's authenticated session. Fixation, cleartext
credential transport, and stale server side sessions have different lifecycle controls. Report the
line that preserves or accepts the usable identifier, how the attacker obtains it, and which
authenticated action it unlocks.

## Session Fixation

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
    sessions.create(new_session_id, authenticated_user)
    response.set_cookie("sid", new_session_id)
```

The old identifier must become unusable when authentication succeeds. Setting a new cookie without
invalidating a server side session that the attacker still knows does not end fixation.

## Cleartext Session Transport

Vulnerable:

```python
def issue_session(response, session_id):
    response.set_cookie("sid", session_id, secure=False)
```

Secure:

```python
def issue_session(response, session_id):
    response.set_cookie("sid", session_id, secure=True)
```

The vulnerable form is reportable only when the effective deployment permits the session cookie
to cross an attacker observable HTTP connection. The secure flag is meaningful only when the
application and its proxy preserve HTTPS.

## Logout and Expiry

Vulnerable:

```python
def logout(response):
    response.delete_cookie("sid")


def authenticate(sessions, session_id):
    return sessions[session_id]
```

Secure:

```python
def logout(response, sessions, session_id):
    sessions.revoke(session_id)
    response.delete_cookie("sid")


def authenticate(sessions, session_id):
    return sessions.require_active(session_id, idle_seconds=1_800, absolute_seconds=28_800)
```

Client cookie deletion does not revoke a copied credential. The server must reject revoked,
idle-expired, and absolute-expired identifiers before authorizing a request.

## Not a Finding

A session id regenerated at authentication and rejected after logout, idle expiry, and absolute
expiry is not fixed or indefinite. A cookie without `Secure` in a local test configuration is not a
production transport finding. Missing `HttpOnly` alone does not create script execution, and
missing `SameSite` alone belongs to a concrete CSRF analysis. Do not report a source default when a
reachable deployment configuration visibly supplies the effective secure value.
