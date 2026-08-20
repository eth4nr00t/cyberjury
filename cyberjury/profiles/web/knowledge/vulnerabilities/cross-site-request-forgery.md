---
id: cross-site-request-forgery
title: Cross-Site Request Forgery
impact: HIGH
tags: [cwe-352, owasp-a01]
selection_hints: ["methods=[\"POST\"", "methods=['POST'", "@app.post", "router.post", "csrf_exempt", "@csrf_exempt", "SameSite=None", "CSRF_TRUSTED_ORIGINS", "validate_csrf", "csrf"]
---

# Cross-Site Request Forgery

A state-changing request is vulnerable when the browser supplies the victim's ambient credential
and the server does not require a request value that an attacker site cannot provide. A malicious
site can then submit the request as the victim and change account data, transfer value, or perform
another privileged action. Report the state-changing handler where the action is committed, and
show the ambient credential plus the missing token, origin validation, or effective SameSite
boundary.

## Ambient Credential State Changes

Vulnerable:

```python
def change_email(request, current_user, db):
    current_user.email = request.form["email"]
    db.commit()
```

Secure:

```python
def change_email(request, current_user, db, csrf):
    csrf.validate(request.form["csrf_token"])
    current_user.email = request.form["email"]
    db.commit()
```

## OAuth Login CSRF

An OAuth callback that redeems the `code` and starts a session is a state changing request. When it
does not check a `state` value bound to the user's session, an attacker can hand the victim a code
from the attacker's account and log the victim into it. This is login CSRF.

Vulnerable:

```python
def callback(request, exchange_code, login):
    token = exchange_code(request.args["code"])
    login(token)
```

Secure:

```python
import hmac
import secrets


def start_oauth(session, build_authorize_url):
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    return build_authorize_url(state)


def callback(request, session, exchange_code, login):
    state = request.args["state"]
    if not hmac.compare_digest(state, session.pop("oauth_state")):
        raise PermissionError("invalid OAuth state")
    token = exchange_code(request.args["code"])
    login(token)
```

## Not a Finding

An endpoint authenticated only by a bearer token read by JavaScript and sent in the
`Authorization` header is not CSRF because the browser does not attach that credential to an
attacker site's request automatically. A valid anti-CSRF token bound to the session is the
expected control. SameSite cookies are safe only when their effective policy prevents the
cross-site request being reviewed. Do not infer safety from a cookie setting that is overridden
elsewhere or from an unsupported user agent assumption.
